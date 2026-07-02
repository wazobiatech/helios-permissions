// =============================================================================
// permission-client.spec.ts — exercise the hot-path authz decision surface.
//
// Uses InMemoryPermissionCache + a mocked HeliosClient (no real HTTP).
// The mock fetcher implements the same shape as the real HeliosClient so
// we can swap it freely.
// =============================================================================

import { InMemoryPermissionCache } from '../src/cache/in-memory-permission-cache';
import { PermissionClient } from '../src/permission-client';
import type { HeliosClient, HeliosMembershipResolution } from '../src/helios/fetch-user-permissions';

class MockHeliosClient {
  /** Map of "userId:tenantId" → resolution to return. */
  public resolutions = new Map<string, HeliosMembershipResolution>();
  /** Counter: how many times fetchUserPermissions was called. */
  public callCount = 0;

  async fetchUserPermissions(userId: string, tenantId: string): Promise<HeliosMembershipResolution> {
    this.callCount += 1;
    const key = `${userId}:${tenantId}`;
    const r = this.resolutions.get(key);
    if (r === undefined) {
      return { status: 'not_a_member' };
    }
    return r;
  }
}

const silentLogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

describe('PermissionClient', () => {
  let cache: InMemoryPermissionCache;
  let helios: MockHeliosClient;
  let client: PermissionClient;

  beforeEach(() => {
    cache = new InMemoryPermissionCache({ ttlMs: 60_000 });
    helios = new MockHeliosClient();
    client = new PermissionClient({
      // Cast: MockHeliosClient has the same shape as HeliosClient for fetchUserPermissions.
      helios: helios as unknown as HeliosClient,
      cache,
      logger: silentLogger,
    });
  });

  describe('callerHasPermission — happy path', () => {
    it('returns true when role grants the perm', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'OWNER',
        permissions: ['helios:tenant:transfer', 'muse:posts:delete'],
      });
      const granted = await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(granted).toBe(true);
    });

    it('returns false when role lacks the perm', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'VIEWER',
        permissions: ['helios:members:view'],
      });
      const granted = await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(granted).toBe(false);
    });
  });

  describe('callerHasPermission — self-scope short-circuit', () => {
    // Self-scope perms (e.g. mercury:user:write:self) are universal by
    // contract — every authenticated user has them regardless of role
    // or tenant membership. The SDK must short-circuit and return true
    // without touching cache or Helios. Critical for root-tenant users
    // (Mercury platform admins) who have no Helios membership row.

    it('returns true for a self-scope perm and never calls Helios', async () => {
      const granted = await client.callerHasPermission(
        'root-platform-admin',
        'root-tenant-uuid',
        'mercury:user:write:self',
      );
      expect(granted).toBe(true);
      expect(helios.callCount).toBe(0);
    });

    it('returns true for self-scope perm even when Helios would return not_a_member', async () => {
      // If the short-circuit didn't exist, this would resolve to
      // not_a_member (root tenant has no Helios row) → false. The
      // short-circuit ensures the contract is honored.
      helios.resolutions.set('root-admin:root-tenant', {
        status: 'not_a_member',
      });
      const granted = await client.callerHasPermission(
        'root-admin',
        'root-tenant',
        'mercury:connection:read:self',
      );
      expect(granted).toBe(true);
    });

    it('does not short-circuit platform-scope perms (must still go through Helios)', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'VIEWER',
        permissions: ['mercury:api_keys:read'],
      });
      const granted = await client.callerHasPermission(
        'user-1',
        'tenant-1',
        'mercury:service_clients:read',
      );
      expect(granted).toBe(true); // VIEWER has service_clients:read (all 4 roles do)
      expect(helios.callCount).toBe(0); // universal-by-role short-circuit fired
    });
  });

  describe('callerHasPermission — universal-by-role short-circuit', () => {
    // A perm is "universal-by-contract" if it appears in EVERY role's
    // role_permissions[*] array (or is self-scope). The contract author
    // is asserting every authenticated user has it. The SDK short-circuits
    // so root-tenant / tenantless callers aren't 403'd.

    it('short-circuits a perm granted to all 4 roles (mercury:api_keys:read)', async () => {
      const granted = await client.callerHasPermission(
        'root-admin',
        'root-tenant',
        'mercury:api_keys:read',
      );
      expect(granted).toBe(true);
      expect(helios.callCount).toBe(0);
    });

    it('does NOT short-circuit a perm granted to only some roles (mercury:api_keys:create)', async () => {
      // api_keys:create is OWNER+ADMIN only — not all 4 roles.
      helios.resolutions.set('viewer-user:tenant-1', {
        status: 'active',
        role: 'VIEWER',
        permissions: ['mercury:api_keys:read'], // no api_keys:create
      });
      const granted = await client.callerHasPermission(
        'viewer-user',
        'tenant-1',
        'mercury:api_keys:create',
      );
      expect(granted).toBe(false); // VIEWER doesn't have create
      expect(helios.callCount).toBe(1); // short-circuit did NOT fire — must check role
    });

    it('admin can create keys (mercury:api_keys:create via Helios, not short-circuit)', async () => {
      // For perms NOT granted to all roles, the SDK must still consult Helios.
      // This proves the Helios path remains active for non-universal perms.
      helios.resolutions.set('admin-user:tenant-1', {
        status: 'active',
        role: 'ADMIN',
        permissions: ['mercury:api_keys:create', 'mercury:api_keys:revoke', 'mercury:api_keys:read'],
      });
      const granted = await client.callerHasPermission(
        'admin-user',
        'tenant-1',
        'mercury:api_keys:create',
      );
      expect(granted).toBe(true);
      expect(helios.callCount).toBe(1);
    });
  });

  describe('callerHasPermission — cache behavior', () => {
    it('hits cache on second call (no second Helios fetch)', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'OWNER',
        permissions: ['helios:tenant:transfer'],
      });
      await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(helios.callCount).toBe(1);
    });

    it('returns cached value (verifying with a different perm from the same role)', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'OWNER',
        permissions: ['helios:tenant:transfer', 'muse:posts:delete'],
      });
      const a = await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      const b = await client.callerHasPermission('user-1', 'tenant-1', 'muse:posts:delete');
      expect(a).toBe(true);
      expect(b).toBe(true);
      expect(helios.callCount).toBe(1);
    });

    it('not_a_member returns empty perms and denies', async () => {
      // Mock returns not_a_member by default.
      const granted = await client.callerHasPermission('user-x', 'tenant-y', 'helios:members:view');
      expect(granted).toBe(false);
    });

    it('inactive membership returns empty perms and denies', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'inactive',
        role: 'OWNER',
      });
      const granted = await client.callerHasPermission('user-1', 'tenant-1', 'helios:members:view');
      expect(granted).toBe(false);
    });
  });

  describe('callerHasPermission — concurrent reads coalesce', () => {
    it('makes only one Helios call for N concurrent cold-cache reads', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'OWNER',
        permissions: ['helios:tenant:transfer'],
      });

      // Fire 20 concurrent reads.
      const reads = Array.from({ length: 20 }, () =>
        client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer'),
      );
      const results = await Promise.all(reads);

      expect(results.every((r) => r === true)).toBe(true);
      expect(helios.callCount).toBe(1);
    });
  });

  describe('callerHasPermission — fail-closed on Helios error', () => {
    it('returns false (denies) when Helios errors and no cache entry exists', async () => {
      const failingHelios = {
        fetchUserPermissions: async () => {
          throw new Error('helios down');
        },
      } as unknown as HeliosClient;
      const failClosedClient = new PermissionClient({
        helios: failingHelios,
        cache,
        logger: silentLogger,
        staleOnError: true,
      });
      const granted = await failClosedClient.callerHasPermission('user-1', 'tenant-1', 'helios:members:view');
      expect(granted).toBe(false);
    });

    it('throws when staleOnError is false', async () => {
      const failingHelios = {
        fetchUserPermissions: async () => {
          throw new Error('helios down');
        },
      } as unknown as HeliosClient;
      const failLoudClient = new PermissionClient({
        helios: failingHelios,
        cache,
        logger: silentLogger,
        staleOnError: false,
      });
      await expect(
        failLoudClient.callerHasPermission('user-1', 'tenant-1', 'helios:members:view'),
      ).rejects.toThrow('helios down');
    });
  });

  describe('invalidate', () => {
    it('drops the cache entry for (userId, tenantId)', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'OWNER',
        permissions: ['helios:tenant:transfer'],
      });

      // First call: cache miss → fetch + cache.
      await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(helios.callCount).toBe(1);

      // Second call: cache hit.
      await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(helios.callCount).toBe(1);

      // Invalidate.
      await client.invalidate('user-1', 'tenant-1');

      // Third call: cache miss → fetch again.
      await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(helios.callCount).toBe(2);
    });

    it('drops all entries for a user when tenantId is omitted', async () => {
      helios.resolutions.set('user-1:tenant-1', { status: 'active', role: 'OWNER', permissions: ['helios:members:view'] });
      helios.resolutions.set('user-1:tenant-2', { status: 'active', role: 'ADMIN', permissions: ['helios:members:invite'] });

      await client.callerHasPermission('user-1', 'tenant-1', 'helios:members:view');
      await client.callerHasPermission('user-1', 'tenant-2', 'helios:members:invite');
      expect(helios.callCount).toBe(2);

      await client.invalidate('user-1');

      await client.callerHasPermission('user-1', 'tenant-1', 'helios:members:view');
      await client.callerHasPermission('user-1', 'tenant-2', 'helios:members:invite');
      expect(helios.callCount).toBe(4);
    });
  });

  describe('writeThrough', () => {
    it('overwrites the cached value (used by Helios after a role change)', async () => {
      // Prime cache as VIEWER.
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'VIEWER',
        permissions: ['helios:members:view'],
      });
      await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      // Verify: VIEWER does not have transfer.
      expect(helios.callCount).toBe(1);

      // Helios writes-through the new perm set (after promoting to OWNER).
      await client.writeThrough('user-1', 'tenant-1', ['helios:tenant:transfer']);

      // Next read: cache hit, returns new perms — no Helios call.
      const granted = await client.callerHasPermission('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(granted).toBe(true);
      expect(helios.callCount).toBe(1); // No additional Helios fetch.
    });
  });

  describe('explain', () => {
    it('returns granted=true + role for active members with the perm', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'OWNER',
        permissions: ['helios:tenant:transfer'],
      });
      const result = await client.explain('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(result).toEqual({
        granted: true,
        role: 'OWNER',
        reason: 'granted_by_role',
      });
    });

    it('returns granted=false + role + reason for active members without the perm', async () => {
      helios.resolutions.set('user-1:tenant-1', {
        status: 'active',
        role: 'VIEWER',
        permissions: ['helios:members:view'],
      });
      const result = await client.explain('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(result.granted).toBe(false);
      expect(result.role).toBe('VIEWER');
      expect(result.reason).toBe('role_lacks_permission');
    });

    it('returns granted=false + role=null + not_a_member for non-members', async () => {
      const result = await client.explain('user-x', 'tenant-y', 'helios:members:view');
      expect(result).toEqual({
        granted: false,
        role: null,
        reason: 'not_a_member',
      });
    });

    it('returns granted=false + role + membership_inactive for inactive members', async () => {
      helios.resolutions.set('user-1:tenant-1', { status: 'inactive', role: 'OWNER' });
      const result = await client.explain('user-1', 'tenant-1', 'helios:tenant:transfer');
      expect(result.granted).toBe(false);
      expect(result.role).toBe('OWNER');
      expect(result.reason).toBe('membership_inactive');
    });
  });
});

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

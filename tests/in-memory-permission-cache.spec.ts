// =============================================================================
// in-memory-permission-cache.spec.ts — exercise the Map-backed impl.
//
// These tests cover the cache contract; the Redis impl has the same
// contract (verified via shared interface), so passing tests here means
// the Redis impl should behave correctly too (modulo Redis-specific edge
// cases verified separately if needed).
// =============================================================================

import { InMemoryPermissionCache } from '../src/cache/in-memory-permission-cache';

describe('InMemoryPermissionCache', () => {
  let cache: InMemoryPermissionCache;
  let now: number;

  beforeEach(() => {
    now = 1_000_000;
    cache = new InMemoryPermissionCache({
      ttlMs: 60_000,
      now: () => now,
    });
  });

  describe('get / set', () => {
    it('returns null on miss', async () => {
      expect(await cache.get('user-1', 'tenant-1')).toBeNull();
    });

    it('returns the cached value on hit', async () => {
      await cache.set('user-1', 'tenant-1', ['helios:members:view']);
      expect(await cache.get('user-1', 'tenant-1')).toEqual(['helios:members:view']);
    });

    it('negative caching: empty array means user is not a member', async () => {
      await cache.set('user-1', 'tenant-1', []);
      const result = await cache.get('user-1', 'tenant-1');
      expect(result).not.toBeNull();
      expect(result).toEqual([]);
    });
  });

  describe('NX semantics on set', () => {
    it('does not overwrite an existing live entry', async () => {
      await cache.set('user-1', 'tenant-1', ['helios:members:view']);
      await cache.set('user-1', 'tenant-1', ['helios:members:invite']);
      const result = await cache.get('user-1', 'tenant-1');
      expect(result).toEqual(['helios:members:view']);
    });

    it('writes when existing entry is expired', async () => {
      await cache.set('user-1', 'tenant-1', ['helios:members:view']);
      now += 70_000; // past TTL
      await cache.set('user-1', 'tenant-1', ['helios:members:invite']);
      const result = await cache.get('user-1', 'tenant-1');
      expect(result).toEqual(['helios:members:invite']);
    });
  });

  describe('writeThrough', () => {
    it('overwrites unconditionally (no NX)', async () => {
      await cache.set('user-1', 'tenant-1', ['helios:members:view']);
      await cache.writeThrough('user-1', 'tenant-1', ['helios:members:invite']);
      const result = await cache.get('user-1', 'tenant-1');
      expect(result).toEqual(['helios:members:invite']);
    });
  });

  describe('invalidate', () => {
    it('drops a specific (userId, tenantId) entry', async () => {
      await cache.set('user-1', 'tenant-1', ['helios:members:view']);
      await cache.set('user-1', 'tenant-2', ['helios:members:invite']);
      await cache.invalidate('user-1', 'tenant-1');
      expect(await cache.get('user-1', 'tenant-1')).toBeNull();
      expect(await cache.get('user-1', 'tenant-2')).not.toBeNull();
    });

    it('drops all entries for a userId when tenantId is omitted', async () => {
      await cache.set('user-1', 'tenant-1', ['helios:members:view']);
      await cache.set('user-1', 'tenant-2', ['helios:members:invite']);
      await cache.set('user-2', 'tenant-1', ['helios:roles:assign']);
      await cache.invalidate('user-1');
      expect(await cache.get('user-1', 'tenant-1')).toBeNull();
      expect(await cache.get('user-1', 'tenant-2')).toBeNull();
      expect(await cache.get('user-2', 'tenant-1')).not.toBeNull();
    });
  });

  describe('invalidateTenant', () => {
    it('drops all entries for a tenant (every user)', async () => {
      await cache.set('user-1', 'tenant-1', ['helios:members:view']);
      await cache.set('user-2', 'tenant-1', ['helios:members:invite']);
      await cache.set('user-1', 'tenant-2', ['helios:roles:assign']);
      await cache.invalidateTenant('tenant-1');
      expect(await cache.get('user-1', 'tenant-1')).toBeNull();
      expect(await cache.get('user-2', 'tenant-1')).toBeNull();
      expect(await cache.get('user-1', 'tenant-2')).not.toBeNull();
    });
  });

  describe('TTL', () => {
    it('expires entries after ttlMs', async () => {
      await cache.set('user-1', 'tenant-1', ['helios:members:view']);
      expect(await cache.get('user-1', 'tenant-1')).not.toBeNull();
      now += 60_001;
      expect(await cache.get('user-1', 'tenant-1')).toBeNull();
    });
  });
});

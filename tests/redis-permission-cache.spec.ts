// =============================================================================
// redis-permission-cache.spec.ts — exercise the Redis impl via ioredis-mock.
//
// Uses ioredis-mock so tests don't need a real Redis. The mock implements
// the ioredis API surface we use (GET, SET with EX+NX, DEL, SCAN).
// =============================================================================

import RedisMock from 'ioredis-mock';

import { RedisPermissionCache } from '../src/cache/redis-permission-cache';
import type { Permission } from '../src/role-permissions';

const silentLogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

describe('RedisPermissionCache', () => {
  let redis: InstanceType<typeof RedisMock>;
  let cache: RedisPermissionCache;

  beforeEach(() => {
    redis = new RedisMock();
    cache = new RedisPermissionCache({
      redis: redis as unknown as import('ioredis').Redis,
      ttlSeconds: 60,
      logger: silentLogger,
    });
  });

  afterEach(async () => {
    await redis.flushall();
    await redis.quit();
  });

  it('returns null on miss', async () => {
    expect(await cache.get('user-1', 'tenant-1')).toBeNull();
  });

  it('returns the cached value on hit', async () => {
    await cache.set('user-1', 'tenant-1', ['helios:members:view']);
    const result = await cache.get('user-1', 'tenant-1');
    expect(result).toEqual(['helios:members:view']);
  });

  it('uses SET with NX (does not overwrite an existing live entry)', async () => {
    await cache.set('user-1', 'tenant-1', ['helios:members:view']);
    await cache.set('user-1', 'tenant-1', ['helios:members:invite']);
    const result = await cache.get('user-1', 'tenant-1');
    expect(result).toEqual(['helios:members:view']);
  });

  it('writeThrough overwrites unconditionally', async () => {
    await cache.set('user-1', 'tenant-1', ['helios:members:view']);
    await cache.writeThrough('user-1', 'tenant-1', ['helios:members:invite']);
    const result = await cache.get('user-1', 'tenant-1');
    expect(result).toEqual(['helios:members:invite']);
  });

  it('invalidate(userId, tenantId) deletes just that entry', async () => {
    await cache.set('user-1', 'tenant-1', ['helios:members:view']);
    await cache.set('user-1', 'tenant-2', ['helios:members:invite']);
    await cache.invalidate('user-1', 'tenant-1');
    expect(await cache.get('user-1', 'tenant-1')).toBeNull();
    expect(await cache.get('user-1', 'tenant-2')).toEqual(['helios:members:invite']);
  });

  it('invalidate(userId) drops every entry for that user (SCAN + DEL)', async () => {
    await cache.set('user-1', 'tenant-1', ['helios:members:view']);
    await cache.set('user-1', 'tenant-2', ['helios:members:invite']);
    await cache.set('user-2', 'tenant-1', ['helios:roles:assign']);
    await cache.invalidate('user-1');
    expect(await cache.get('user-1', 'tenant-1')).toBeNull();
    expect(await cache.get('user-1', 'tenant-2')).toBeNull();
    expect(await cache.get('user-2', 'tenant-1')).toEqual(['helios:roles:assign']);
  });

  it('invalidateTenant drops every entry for a tenant', async () => {
    await cache.set('user-1', 'tenant-1', ['helios:members:view']);
    await cache.set('user-2', 'tenant-1', ['helios:members:invite']);
    await cache.set('user-1', 'tenant-2', ['helios:roles:assign']);
    await cache.invalidateTenant('tenant-1');
    expect(await cache.get('user-1', 'tenant-1')).toBeNull();
    expect(await cache.get('user-2', 'tenant-1')).toBeNull();
    expect(await cache.get('user-1', 'tenant-2')).toEqual(['helios:roles:assign']);
  });

  it('serializes perms as JSON (cross-language compat)', async () => {
    const perms: Permission[] = [
      'helios:members:view',
      'helios:tenant:transfer',
      'muse:posts:write',
    ];
    await cache.set('user-1', 'tenant-1', perms);
    const raw = await redis.get('helios:perms:user-1:tenant-1');
    expect(raw).toBe(JSON.stringify(perms));
  });

  it('TTL is set on writes (bounded staleness)', async () => {
    await cache.set('user-1', 'tenant-1', ['helios:members:view']);
    const ttl = await redis.ttl('helios:perms:user-1:tenant-1');
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(60);
  });

  it('returns null and does not throw when Redis errors on GET', async () => {
    const brokenRedis = {
      get: async () => {
        throw new Error('redis down');
      },
      set: async () => undefined,
      scan: async () => ['0', []] as [string, string[]],
      del: async () => 0,
    } as unknown as import('ioredis').Redis;
    const brokenCache = new RedisPermissionCache({
      redis: brokenRedis,
      ttlSeconds: 60,
      logger: silentLogger,
    });
    expect(await brokenCache.get('user-1', 'tenant-1')).toBeNull();
  });

  it('does not throw when Redis errors on SET (best-effort)', async () => {
    const brokenRedis = {
      get: async () => null,
      set: async () => {
        throw new Error('redis down');
      },
      scan: async () => ['0', []] as [string, string[]],
      del: async () => 0,
    } as unknown as import('ioredis').Redis;
    const brokenCache = new RedisPermissionCache({
      redis: brokenRedis,
      ttlSeconds: 60,
      logger: silentLogger,
    });
    await expect(brokenCache.set('user-1', 'tenant-1', ['helios:members:view'])).resolves.toBeUndefined();
  });

  it('throws when Redis errors on DEL (invalidate is the dangerous path)', async () => {
    const brokenRedis = {
      get: async () => null,
      set: async () => undefined,
      scan: async () => ['0', []] as [string, string[]],
      del: async () => {
        throw new Error('redis down');
      },
    } as unknown as import('ioredis').Redis;
    const brokenCache = new RedisPermissionCache({
      redis: brokenRedis,
      ttlSeconds: 60,
      logger: silentLogger,
    });
    await expect(brokenCache.invalidate('user-1', 'tenant-1')).rejects.toThrow('redis down');
  });
});

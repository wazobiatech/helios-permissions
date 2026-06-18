// =============================================================================
// RedisPermissionCache — production impl backed by Redis.
//
// Connection: ioredis client. Single Redis instance per cluster
// (PERMISSION_REDIS_URL shared by Helios and every downstream service).
//
// Key shape: `helios:perms:{userId}:{tenantId}` -> JSON array of perms.
//
// Invalidation patterns:
//   invalidate(userId)            -> SCAN MATCH helios:perms:{userId}:* DEL
//   invalidate(userId, tenantId)  -> DEL helios:perms:{userId}:{tenantId}
//   invalidateTenant(tenantId)    -> SCAN MATCH helios:perms:*:{tenantId} DEL
//
// SCAN is non-blocking (KEYS would block the Redis event loop on a large
// keyspace — never use KEYS in production).
//
// Error handling:
//   - GET failures: log warn + return null. Caller falls through to Helios.
//   - SET / writeThrough failures: log warn + swallow. Cache is best-effort.
//   - Invalidate failures: log error + throw. The caller (event consumer
//     or Helios service) needs to know cache may be stale. The TTL is
//     the bound — 60s of staleness is the worst case.
//
// Why the error asymmetry:
//   - Reads / writes that fail are degraded-but-correct paths (Helios is
//     the source of truth).
//   - Invalidation failures leave stale data with no automatic recovery
//     except TTL expiry. Operators need visibility.
// =============================================================================

import type Redis from 'ioredis';

import type { Permission } from '../role-permissions';
import type { Logger } from '../types/logger';
import type { PermissionCache } from './permission-cache.interface';

const KEY_PREFIX = 'helios:perms:';

/** Default TTL: 60 seconds. Bounds staleness when invalidation fails. */
export const DEFAULT_CACHE_TTL_SECONDS = 60;

/** SCAN batch size — balances round-trip count vs cursor overhead. */
const SCAN_BATCH = 100;

export interface RedisPermissionCacheOptions {
  /** Configured ioredis client. Caller owns the connection lifecycle. */
  redis: Redis;
  /** TTL in seconds. Default 60. */
  ttlSeconds?: number;
  /** Logger for diagnostics. Defaults to silent. */
  logger?: Logger;
}

export class RedisPermissionCache implements PermissionCache {
  private readonly redis: Redis;
  private readonly ttlSeconds: number;
  private readonly logger: Logger;

  constructor(opts: RedisPermissionCacheOptions) {
    this.redis = opts.redis;
    this.ttlSeconds = opts.ttlSeconds ?? DEFAULT_CACHE_TTL_SECONDS;
    this.logger = opts.logger ?? {
      debug: () => undefined,
      info: () => undefined,
      warn: () => undefined,
      error: () => undefined,
    };
  }

  // ---------------------------------------------------------------------------
  // Key helpers
  // ---------------------------------------------------------------------------

  private key(userId: string, tenantId: string): string {
    return `${KEY_PREFIX}${userId}:${tenantId}`;
  }

  private userPattern(userId: string): string {
    return `${KEY_PREFIX}${userId}:*`;
  }

  private tenantPattern(tenantId: string): string {
    return `${KEY_PREFIX}*:${tenantId}`;
  }

  // ---------------------------------------------------------------------------
  // Reads
  // ---------------------------------------------------------------------------

  async get(userId: string, tenantId: string): Promise<Permission[] | null> {
    try {
      const raw = await this.redis.get(this.key(userId, tenantId));
      if (raw === null) return null;
      const parsed = JSON.parse(raw) as unknown;
      if (!Array.isArray(parsed)) {
        // Corrupt entry — treat as miss.
        this.logger.warn(
          { userId, tenantId, raw },
          'RedisPermissionCache.get: cached value is not an array, treating as miss',
        );
        return null;
      }
      return parsed as Permission[];
    } catch (err) {
      this.logger.warn(
        { err, userId, tenantId },
        'RedisPermissionCache.get failed, returning null (caller falls through to Helios)',
      );
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Writes
  // ---------------------------------------------------------------------------

  async set(userId: string, tenantId: string, perms: Permission[]): Promise<void> {
    try {
      // NX = only set if not exists. Prevents a slow in-flight read from
      // resurrecting a value that was invalidated after the read started.
      // The TTL is the safety net for missed invalidations.
      await this.redis.set(
        this.key(userId, tenantId),
        JSON.stringify(perms),
        'EX',
        this.ttlSeconds,
        'NX',
      );
    } catch (err) {
      this.logger.warn(
        { err, userId, tenantId },
        'RedisPermissionCache.set failed, continuing without cache',
      );
    }
  }

  async writeThrough(
    userId: string,
    tenantId: string,
    perms: Permission[],
  ): Promise<void> {
    try {
      // No NX — write-through explicitly overwrites. Helios calls this
      // after it knows the new value is correct (e.g. after a role
      // change in user_projects). We want the next read to see the new
      // value immediately, not race with a stale cache entry.
      await this.redis.set(
        this.key(userId, tenantId),
        JSON.stringify(perms),
        'EX',
        this.ttlSeconds,
      );
    } catch (err) {
      this.logger.warn(
        { err, userId, tenantId },
        'RedisPermissionCache.writeThrough failed, continuing without cache',
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Invalidation
  // ---------------------------------------------------------------------------

  async invalidate(userId: string, tenantId?: string): Promise<void> {
    try {
      if (tenantId === undefined) {
        await this.scanAndDelete(this.userPattern(userId));
      } else {
        const deleted = await this.redis.del(this.key(userId, tenantId));
        this.logger.info(
          { userId, tenantId, deleted },
          'RedisPermissionCache.invalidate: deleted (userId, tenantId) entry',
        );
      }
    } catch (err) {
      this.logger.error(
        { err, userId, tenantId },
        'RedisPermissionCache.invalidate failed — cache may be stale for up to TTL seconds',
      );
      throw err;
    }
  }

  async invalidateTenant(tenantId: string): Promise<void> {
    try {
      const deleted = await this.scanAndDelete(this.tenantPattern(tenantId));
      this.logger.info(
        { tenantId, deleted },
        'RedisPermissionCache.invalidateTenant: deleted all entries for tenant',
      );
    } catch (err) {
      this.logger.error(
        { err, tenantId },
        'RedisPermissionCache.invalidateTenant failed — cache may be stale for up to TTL seconds',
      );
      throw err;
    }
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  /**
   * SCAN-based batched DEL. Non-blocking — unlike KEYS which blocks the
   * Redis event loop on a large keyspace. Cursor-based iteration with
   * batched DEL per page.
   *
   * Returns the total count of keys deleted.
   */
  private async scanAndDelete(pattern: string): Promise<number> {
    let cursor = '0';
    let totalDeleted = 0;
    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        SCAN_BATCH,
      );
      cursor = nextCursor;
      if (keys.length > 0) {
        const deleted = await this.redis.del(...keys);
        totalDeleted += deleted;
      }
    } while (cursor !== '0');
    return totalDeleted;
  }
}

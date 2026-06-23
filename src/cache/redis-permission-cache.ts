// =============================================================================
// RedisPermissionCache — production impl backed by Redis.
//
// Connection: ioredis client. Single Redis instance per cluster
// (PERMISSION_REDIS_URL shared by Helios and every downstream service).
//
// Key shape: `helios:perms:{userId}:{tenantId}` -> JSON array of perms.
//
// TTL policy (no expiry by default):
//   The cache is the primary read path for callerHasPermission. We aim
//   for a 90-98% hit rate, which means entries must outlive the
//   request burst. Every entry is invalidated explicitly at the
//   mutation site (Helios calls invalidate/writeThrough after each
//   role change, Hecate's event consumer drops the key on
//   helios.* events). A TTL safety-net would only force needless
//   re-population; remove it by default.
//
//   Pass `ttlSeconds: <positive int>` to opt back into a TTL. Useful
//   for staging environments with churn that blows up the keyspace.
//   When set, every write below passes EX explicitly. When unset
//   (the default), writes pass no EX argument and Redis keeps the
//   key forever until explicit DEL.
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
//     or Helios service) needs to know cache may be stale. With no TTL,
//     a failed invalidation is sticky until the next writeThrough for
//     that user; that is the operator-visible signal.
// =============================================================================

import type Redis from 'ioredis';

import type { Permission } from '../role-permissions';
import type { Logger } from '../types/logger';
import type { PermissionCache } from './permission-cache.interface';

const KEY_PREFIX = 'helios:perms:';

/**
 * Default TTL: none (PERMANENT). Entries are refreshed only by
 * explicit writeThrough / invalidate calls. Override per-instance via
 * the `ttlSeconds` constructor option.
 *
 * Historical note: v0.3.0 shipped with a 60s default TTL as a "safety
 * net" for missed invalidations. It was removed when the team moved to
 * a write-through model — the explicit invalidates on every mutation
 * make the TTL redundant, and a 90-98% cache-hit-rate platform needs
 * the entries to stick around.
 */
export const DEFAULT_CACHE_TTL_SECONDS = 0;

/** SCAN batch size — balances round-trip count vs cursor overhead. */
const SCAN_BATCH = 100;

export interface RedisPermissionCacheOptions {
  /** Configured ioredis client. Caller owns the connection lifecycle. */
  redis: Redis;
  /**
   * TTL in seconds. Default 0 (no expiry — Redis PERSIST semantics).
   * Pass any positive integer to opt back into a TTL.
   *
   * IMPORTANT: must match the Helios-side cache (the
   * `PermissionCacheService.writeThrough` write). If Helios writes with
   * one TTL and the SDK reads with another, the SDK's EX will win on
   * the next SDK-side `set` call and may drop entries before Helios
   * has a chance to re-write them.
   */
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
      //
      // TTL: only set EX when ttlSeconds > 0. ttlSeconds === 0 (default)
      // means "no expiry"; ioredis omits EX and Redis keeps the key
      // until explicit DEL. We do NOT pass KEEPTTL here — this is a
      // fresh write, not a re-write.
      if (this.ttlSeconds > 0) {
        await this.redis.set(
          this.key(userId, tenantId),
          JSON.stringify(perms),
          'EX',
          this.ttlSeconds,
          'NX',
        );
      } else {
        await this.redis.set(
          this.key(userId, tenantId),
          JSON.stringify(perms),
          'NX',
        );
      }
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
      //
      // TTL: same policy as set() — only pass EX when configured. No
      // KEEPTTL — this is an overwrite, not a refresh.
      if (this.ttlSeconds > 0) {
        await this.redis.set(
          this.key(userId, tenantId),
          JSON.stringify(perms),
          'EX',
          this.ttlSeconds,
        );
      } else {
        await this.redis.set(
          this.key(userId, tenantId),
          JSON.stringify(perms),
        );
      }
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
        'RedisPermissionCache.invalidate failed — cache will stay stale until the next writeThrough for this user',
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
        'RedisPermissionCache.invalidateTenant failed — affected entries will be re-written on the next role change for each user',
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

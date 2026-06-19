// =============================================================================
// createPermissionClient — convenience factory.
//
// Composes:
//   - RedisPermissionCache (or InMemoryPermissionCache for tests)
//   - HeliosClient (HMAC-signed GET)
//   - PermissionClient (the cache-first authz decision surface)
//
// Caller injects the Redis connection (we don't own the connection
// lifecycle) and the logger (NestJS's Logger satisfies the interface).
//
// Authentication (v0.2.0):
//   - The Helios route is HMAC-only. `signatureSharedSecret` is the
//     only auth surface (env var: `SIGNATURE_SHARED_SECRET`).
// =============================================================================

import Redis, { type Redis as RedisType } from 'ioredis';

import { PermissionClient } from './permission-client';
import type { PermissionClientOptions } from './permission-client';
import {
  DEFAULT_CACHE_TTL_SECONDS,
  RedisPermissionCache,
} from './cache/redis-permission-cache';
import { HeliosClient } from './helios/fetch-user-permissions';
import type { Logger } from './types/logger';
import { silentLogger } from './types/logger';

export interface CreatePermissionClientOptions {
  /** Helios base URL. e.g. `https://helios.internal` */
  heliosBaseUrl: string;
  /**
   * HMAC secret shared with Helios. Canonical env var name is
   * `SIGNATURE_SHARED_SECRET` (matches Hecate's convention).
   */
  signatureSharedSecret: string;
  /** Service name sent as x-source-service header. Default 'helios-permissions-sdk'. */
  heliosSourceService?: string;
  /** Redis connection URL. e.g. `redis://helios-permissions-redis:6379/0`. */
  redisUrl: string;
  /** Pre-configured ioredis client. If omitted, one is created from `redisUrl`. */
  redis?: RedisType;
  /** TTL in seconds. Default 60. */
  cacheTtlSeconds?: number;
  /** Logger. Default silent. */
  logger?: Logger;
  /** Behavior on Helios failure when no cache entry exists. Default true (fail-closed). */
  staleOnError?: boolean;
  /** Helios fetch timeout in ms. Default 2000. */
  heliosFetchTimeoutMs?: number;
}

export interface CreatePermissionClientResult {
  client: PermissionClient;
  /** The Redis client we created (or the one passed in). Caller owns lifecycle. */
  redis: RedisType;
  /** Close the Redis connection we created. No-op if caller injected their own. */
  close: () => Promise<void>;
}

export function createPermissionClient(
  opts: CreatePermissionClientOptions,
): CreatePermissionClientResult {
  const logger = opts.logger ?? silentLogger;

  // Redis: use injected client or create one.
  let ownsRedis = false;
  let redis: RedisType;
  if (opts.redis !== undefined) {
    redis = opts.redis;
  } else {
    redis = new Redis(opts.redisUrl, {
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: false,
    });
    ownsRedis = true;
  }

  const cache = new RedisPermissionCache({
    redis,
    ttlSeconds: opts.cacheTtlSeconds ?? DEFAULT_CACHE_TTL_SECONDS,
    logger,
  });

  const helios = new HeliosClient({
    baseUrl: opts.heliosBaseUrl,
    signatureSharedSecret: opts.signatureSharedSecret,
    sourceService: opts.heliosSourceService,
    fetchTimeoutMs: opts.heliosFetchTimeoutMs,
    logger,
  });

  const clientOptions: PermissionClientOptions = {
    helios,
    cache,
    logger,
    staleOnError: opts.staleOnError,
  };
  const client = new PermissionClient(clientOptions);

  return {
    client,
    redis,
    close: async () => {
      if (ownsRedis) {
        await redis.quit().catch(() => undefined);
      }
    },
  };
}

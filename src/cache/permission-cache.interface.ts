// =============================================================================
// PermissionCache interface — the abstraction every cache impl satisfies.
//
// RedisPermissionCache is the production impl. InMemoryPermissionCache is
// the test impl. Helios and downstream services import the interface; the
// impl is injected by the factory.
// =============================================================================

import type { Permission } from '../role-permissions';

/**
 * PermissionCache stores the resolved permission array for a (userId,
 * tenantId) pair. Values are JSON-serializable so TS / Python / Go SDKs
 * can read each other's cache entries (in practice each language runs
 * its own Redis instance, but cross-language compat is the design goal).
 */
export interface PermissionCache {
  /**
   * Returns the cached permission array, or `null` on cache miss.
   *
   * An empty array `[]` is a valid cached value meaning "user is not a
   * member of this tenant" (negative cache). Callers must distinguish
   * `null` (miss, fall through to Helios) from `[]` (hit, deny).
   *
   * Implementation note: implementations MUST NOT throw on Redis errors.
   * Log and return `null` — the caller's fall-through to Helios is the
   * safety net.
   */
  get(userId: string, tenantId: string): Promise<Permission[] | null>;

  /**
   * Stores the permission array with the configured TTL. Uses `SET NX`
   * to avoid resurrecting an entry that was just invalidated (the
   * stale-populate race). TTL is the safety net for missed
   * invalidations.
   *
   * Implementation note: implementations MUST NOT throw on Redis errors.
   * Log and swallow — the cache is best-effort.
   */
  set(userId: string, tenantId: string, perms: Permission[]): Promise<void>;

  /**
   * Overwrite the cached value without the NX guard. Used by Helios for
   * write-through after a perm change — Helios KNOWS the new value is
   * correct and wants to force the update immediately, not wait for the
   * race window to resolve.
   *
   * Same error semantics as `set`: log + swallow on Redis failure.
   */
  writeThrough(userId: string, tenantId: string, perms: Permission[]): Promise<void>;

  /**
   * Drop the cached entry. When `tenantId` is omitted, drops all
   * entries for this user across every tenant (used by member-removed).
   *
   * This is the one cache operation that SHOULD throw on failure. A
   * failed invalidate means stale data may be served until TTL expires;
   * the caller (typically an event consumer) needs to know to retry or
   * page operators.
   */
  invalidate(userId: string, tenantId?: string): Promise<void>;

  /**
   * Drop all cached entries for a tenant (every user). Used when a
   * tenant is deleted — no `helios.member.removed` event fires per-user.
   *
   * Same throw-on-failure semantics as `invalidate`.
   */
  invalidateTenant(tenantId: string): Promise<void>;
}

// =============================================================================
// PermissionClient — the SDK's main surface.
//
// Responsibilities:
//   - callerHasPermission(userId, tenantId, perm) — the hot path every
//     service calls on every authz decision. Redis-cached, with
//     fail-closed behavior on Helios unavailability.
//
//   - getUserPermissions(userId, tenantId) — full perm list (for UI
//     display, not hot-path authz).
//
//   - explain(userId, tenantId, perm) — diagnostic with role + reason
//     for the explain endpoint and audit logs.
//
//   - invalidate(userId, tenantId?) — called by event consumers (and
//     Helios's sync write-through path) to drop stale cache entries.
//
//   - writeThrough(userId, tenantId, perms) — Helios-only path. After
//     updating user_projects, Helios writes the new perm array directly
//     to the cache (no NX), so the next read sees fresh data with no
//     race window.
//
// Failure modes:
//   - Cache miss + Helios OK: fetch + populate cache + return.
//   - Cache miss + Helios error + staleOnError: true → log + return false
//     (fail-closed — deny rather than serve potentially-stale or unknown).
//   - Cache miss + Helios error + staleOnError: false → throw.
//   - Cache hit: return cached value (no Helios call).
//
// Concurrency:
//   - In-process lock per (userId, tenantId) coalesces concurrent
//     cold-cache reads. The first call fetches from Helios; concurrent
//     calls await the same promise.
//   - The TTL (60s default) is the safety net for missed invalidations.
// =============================================================================

import type { PermissionCache } from './cache/permission-cache.interface';
import { HeliosClient, HeliosUnreachableError } from './helios/fetch-user-permissions';
import type { Permission, Role } from './role-permissions';
import {
  isSelfScope,
  SELF_PERMISSIONS,
  ROLE_PERMISSIONS,
  ROLES,
} from './role-permissions';
import type { Logger } from './types/logger';
import { silentLogger } from './types/logger';

/**
 * A perm is "universal-by-contract" — granted to every authenticated caller
 * without consulting Helios — if any of:
 *   1. The perm is `self` scope (universal by invariant 8 of the
 *      permission-contract — every authenticated user has these).
 *   2. The perm is in every role's `role_permissions[*]` array
 *      (granted to OWNER + ADMIN + EDITOR + VIEWER; universal by
 *      contract design, regardless of scope).
 *
 * Why this exists: Helios stores per-(user, tenant) membership rows.
 * Root-tenant users (Mercury's platform admins) and any other tenantless
 * caller have no row to look up. Without this short-circuit, every
 * `callerHasPermission` for a universal perm would resolve to
 * `not_a_member` and 403 the caller. The contract invariant is that
 * these perms do NOT depend on tenant membership — they are universal.
 *
 * The check trusts the contract: if a perm is in every role's perm
 * array, the contract author intends every authenticated user to have
 * it. Adding a perm to all four roles is a deliberate, reviewable
 * contract decision — the SDK honors it without re-fetching.
 */
function isUniversalPerm(perm: Permission): boolean {
  if (isSelfScope(perm)) {
    return true;
  }
  return ROLES.every((role) => ROLE_PERMISSIONS[role].includes(perm));
}

export interface PermissionClientOptions {
  /** Helios HTTP client. */
  helios: HeliosClient;
  /** Permission cache (Redis in production, in-memory in tests). */
  cache: PermissionCache;
  /** Optional logger. Default silent. */
  logger?: Logger;
  /**
   * Behavior on Helios unavailability when no cache entry exists.
   * Default true: log + deny (fail-closed). Set false to throw
   * HeliosUnreachableError so the caller can decide.
   */
  staleOnError?: boolean;
}

export interface PermissionExplanation {
  granted: boolean;
  role: Role | null;
  reason:
    | 'granted_by_role'
    | 'not_a_member'
    | 'membership_inactive'
    | 'role_lacks_permission'
    | 'cache_hit'
    | 'cache_miss_filled_by_helios'
    | 'helios_unreachable_fail_closed';
}

export class PermissionClient {
  private readonly helios: HeliosClient;
  private readonly cache: PermissionCache;
  private readonly logger: Logger;
  private readonly staleOnError: boolean;

  /** Per-key in-flight fetch promise. Coalesces concurrent cold reads. */
  private readonly inFlight = new Map<string, Promise<Permission[]>>();

  constructor(opts: PermissionClientOptions) {
    this.helios = opts.helios;
    this.cache = opts.cache;
    this.logger = opts.logger ?? silentLogger;
    this.staleOnError = opts.staleOnError ?? true;
  }

  // ---------------------------------------------------------------------------
  // Hot path
  // ---------------------------------------------------------------------------

  /**
   * Returns `true` if `userId` is granted `requiredPerm` in `tenantId`.
   *
   * Cache-first: a hit returns immediately. On miss, fetches from
   * Helios and populates the cache. Concurrent misses for the same
   * (userId, tenantId) are coalesced via in-process lock — only one
   * Helios call is made per cold key.
   *
   * Self-scope perms (e.g. `mercury:user:write:self`) are universal by
   * contract — every authenticated user has them regardless of role or
   * tenant membership. We short-circuit on `isSelfScope(requiredPerm)`
   * and return `true` immediately, bypassing the cache and the Helios
   * round-trip. This is critical for root-tenant users (Mercury's
   * platform admins) who have no Helios membership row: without the
   * short-circuit, `callerHasPermission(rootUser, rootTenant, ...)`
   * would resolve to `not_a_member` and deny every self-scope perm.
   *
   * On Helios failure with no cache entry: fail-closed (deny) unless
   * the client was constructed with `staleOnError: false`, in which
   * case the HeliosUnreachableError propagates.
   */
  async callerHasPermission(
    userId: string,
    tenantId: string,
    requiredPerm: Permission,
  ): Promise<boolean> {
    if (isUniversalPerm(requiredPerm)) {
      return true;
    }
    const perms = await this.resolvePerms(userId, tenantId);
    return perms.includes(requiredPerm);
  }

  // ---------------------------------------------------------------------------
  // Display / diagnostic
  // ---------------------------------------------------------------------------

  /**
   * Returns the full permission array for `(userId, tenantId)`. Same
   * cache-first behavior as `callerHasPermission`. An empty array
   * means the user is not a member of the tenant (or the membership
   * is inactive / past expiry).
   *
   * Self-scope perms (e.g. `mercury:user:write:self`) are universal by
   * contract — every authenticated user has them regardless of role or
   * tenant membership. We always fold `SELF_PERMISSIONS` into the result
   * so callers see a complete view. Without this, root-tenant users
   * (Mercury's platform admins, who have no Helios membership row) would
   * show an empty perm array even though they can mutate their own profile.
   */
  async getUserPermissions(userId: string, tenantId: string): Promise<Permission[]> {
    const rolePerms = await this.resolvePerms(userId, tenantId);
    return [...SELF_PERMISSIONS, ...rolePerms];
  }

  /**
   * Diagnostic variant: returns the role, the granted flag, and a
   * reason string for audit logs and the explain endpoint.
   *
   * Note: this method always hits Helios on cache miss (it returns
   * the role, not just the perm array). It's intended for the explain
   * endpoint and audit logging — not for hot-path authz.
   */
  async explain(
    userId: string,
    tenantId: string,
    perm: Permission,
  ): Promise<PermissionExplanation> {
    // Universal perms are granted by contract — no Helios lookup needed.
    if (isUniversalPerm(perm)) {
      return { granted: true, role: null, reason: 'granted_by_role' };
    }
    try {
      const resolution = await this.helios.fetchUserPermissions(userId, tenantId);

      if (resolution.status === 'not_a_member') {
        return {
          granted: false,
          role: null,
          reason: 'not_a_member',
        };
      }

      if (resolution.status === 'inactive') {
        return {
          granted: false,
          role: this.parseRole(resolution.role),
          reason: 'membership_inactive',
        };
      }

      // status === 'active'
      const role = this.parseRole(resolution.role);
      const granted = resolution.permissions.includes(perm);
      return {
        granted,
        role,
        reason: granted ? 'granted_by_role' : 'role_lacks_permission',
      };
    } catch (err) {
      if (err instanceof HeliosUnreachableError) {
        this.logger.error(
          { err, userId, tenantId, perm },
          'PermissionClient.explain: Helios unreachable',
        );
        return {
          granted: false,
          role: null,
          reason: 'helios_unreachable_fail_closed',
        };
      }
      throw err;
    }
  }

  // ---------------------------------------------------------------------------
  // Cache management
  // ---------------------------------------------------------------------------

  /**
   * Drop the cache entry for `(userId, tenantId)`. When `tenantId` is
   * omitted, drops all entries for this user across every tenant.
   *
   * Throws on cache failure (operators need to know — the TTL is the
   * only safety net if DEL fails).
   */
  async invalidate(userId: string, tenantId?: string): Promise<void> {
    await this.cache.invalidate(userId, tenantId);
  }

  /**
   * Drop all cache entries for a tenant. Used when a tenant is deleted.
   */
  async invalidateTenant(tenantId: string): Promise<void> {
    await this.cache.invalidateTenant(tenantId);
  }

  /**
   * Helios-only path. After updating `user_projects`, Helios calls
   * this with the new resolved perm array so the next read sees fresh
   * data without race window.
   *
   * Unlike `set` (which uses NX), this overwrites unconditionally.
   */
  async writeThrough(
    userId: string,
    tenantId: string,
    perms: Permission[],
  ): Promise<void> {
    await this.cache.writeThrough(userId, tenantId, perms);
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  /**
   * Cache-first perm resolution. Handles the in-flight lock, the
   * Helios call, the cache populate, and the fail-closed fallback.
   */
  private async resolvePerms(
    userId: string,
    tenantId: string,
  ): Promise<Permission[]> {
    // 1. Try cache.
    const cached = await this.cache.get(userId, tenantId);
    if (cached !== null) {
      return cached;
    }

    // 2. Cache miss. Coalesce concurrent reads via in-process lock.
    const lockKey = `${userId}:${tenantId}`;
    const existing = this.inFlight.get(lockKey);
    if (existing !== undefined) {
      return existing;
    }

    const fetchPromise = this.fetchAndPopulate(userId, tenantId);
    this.inFlight.set(lockKey, fetchPromise);
    // Suppress unhandled rejection: the inFlight promise's rejection
    // is the caller's rejection (every awaiter sees it). Without the
    // catch, Node logs an unhandled-rejection warning even when the
    // caller awaits it correctly.
    fetchPromise.catch(() => undefined).finally(() => {
      this.inFlight.delete(lockKey);
    });

    return fetchPromise;
  }

  private async fetchAndPopulate(
    userId: string,
    tenantId: string,
  ): Promise<Permission[]> {
    let resolution;
    try {
      resolution = await this.helios.fetchUserPermissions(userId, tenantId);
    } catch (err) {
      if (!this.staleOnError) throw err;
      this.logger.error(
        { err, userId, tenantId },
        'PermissionClient: Helios unreachable, denying (fail-closed)',
      );
      // Fail-closed: return empty perms so all perm checks deny.
      return [];
    }

    const perms = this.resolutionToPerms(resolution);

    // Populate cache (best-effort — set() swallows Redis errors).
    await this.cache.set(userId, tenantId, perms);

    return perms;
  }

  /**
   * Translate Helios's discriminated union into a flat Permission[].
   * - not_a_member → []
   * - inactive → [] (treat as no perms)
   * - active → resolution.permissions verbatim
   */
  private resolutionToPerms(
    resolution: Awaited<ReturnType<HeliosClient['fetchUserPermissions']>>,
  ): Permission[] {
    if (resolution.status === 'active') {
      return resolution.permissions;
    }
    return [];
  }

  /**
   * Parse Helios's role string into the Role union. Defensive — if
   * Helios returns an unknown role (shouldn't happen, but the schema
   * allows strings), return null and the explain endpoint reports it.
   */
  private parseRole(value: string): Role | null {
    switch (value) {
      case 'OWNER':
      case 'ADMIN':
      case 'EDITOR':
      case 'VIEWER':
        return value;
      default:
        return null;
    }
  }
}

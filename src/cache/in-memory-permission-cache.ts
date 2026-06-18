// =============================================================================
// InMemoryPermissionCache — Map-backed impl for tests and single-instance
// dev. Production uses RedisPermissionCache; this impl exists so unit tests
// don't need a Redis instance.
//
// Same interface contract as the Redis impl:
//   - get returns null on miss
//   - set / writeThrough are best-effort (never throw)
//   - invalidate / invalidateTenant throw on failure (no errors possible
//     here, but kept consistent)
// =============================================================================

import type { Permission } from '../role-permissions';
import type { PermissionCache } from './permission-cache.interface';

export interface InMemoryPermissionCacheOptions {
  /** Simulated TTL in ms. Default Infinity (no expiry) for tests. */
  ttlMs?: number;
  /** Optional clock injection for deterministic expiry tests. */
  now?: () => number;
}

interface Entry {
  perms: Permission[];
  expiresAt: number;
}

export class InMemoryPermissionCache implements PermissionCache {
  private readonly store = new Map<string, Entry>();
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(opts: InMemoryPermissionCacheOptions = {}) {
    this.ttlMs = opts.ttlMs ?? Number.POSITIVE_INFINITY;
    this.now = opts.now ?? Date.now;
  }

  private key(userId: string, tenantId: string): string {
    return `${userId}:${tenantId}`;
  }

  private userPattern(userId: string): string {
    return `${userId}:`;
  }

  private tenantPattern(tenantId: string): string {
    return `:${tenantId}`;
  }

  private isExpired(entry: Entry): boolean {
    return entry.expiresAt <= this.now();
  }

  async get(userId: string, tenantId: string): Promise<Permission[] | null> {
    const entry = this.store.get(this.key(userId, tenantId));
    if (entry === undefined) return null;
    if (this.isExpired(entry)) {
      this.store.delete(this.key(userId, tenantId));
      return null;
    }
    return entry.perms;
  }

  async set(userId: string, tenantId: string, perms: Permission[]): Promise<void> {
    const k = this.key(userId, tenantId);
    // NX semantics: don't overwrite an existing live entry.
    const existing = this.store.get(k);
    if (existing !== undefined && !this.isExpired(existing)) return;
    this.store.set(k, { perms, expiresAt: this.now() + this.ttlMs });
  }

  async writeThrough(
    userId: string,
    tenantId: string,
    perms: Permission[],
  ): Promise<void> {
    this.store.set(this.key(userId, tenantId), {
      perms,
      expiresAt: this.now() + this.ttlMs,
    });
  }

  async invalidate(userId: string, tenantId?: string): Promise<void> {
    if (tenantId === undefined) {
      const prefix = this.userPattern(userId);
      for (const k of this.store.keys()) {
        if (k.startsWith(prefix)) this.store.delete(k);
      }
    } else {
      this.store.delete(this.key(userId, tenantId));
    }
  }

  async invalidateTenant(tenantId: string): Promise<void> {
    const suffix = this.tenantPattern(tenantId);
    for (const k of this.store.keys()) {
      if (k.endsWith(suffix)) this.store.delete(k);
    }
  }

  // Test helper — not on the interface.
  size(): number {
    return this.store.size;
  }

  // Test helper — wipe between tests.
  clear(): void {
    this.store.clear();
  }
}

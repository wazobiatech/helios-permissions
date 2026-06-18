// =============================================================================
// helios-permissions — Role → Permission map and helpers.
//
// The Permission union and ROLE_PERMISSIONS map are the canonical source of
// truth for the platform. The Helios service (wazobiatech/helios) imports
// this module via the published package — Helios does NOT redefine the
// map. This guarantees TS / Python / Go / Laravel SDKs that all read the
// same JSON contract agree on what OWNER / ADMIN / EDITOR / VIEWER means.
//
// Permission naming convention: `{service}:{resource}:{action}`.
//   service  — one of: athens, mercury, muse, helios
//   resource — domain noun (project, users, posts, members, ...)
//   action   — verb (view, write, delete, manage, ...)
//
// When a new service is onboarded:
//   1. Add the perm strings to the appropriate `*_PERMISSIONS` tuple below.
//   2. Add the service-prefix to `ROLE_PERMISSIONS` for each role.
//   3. tsc will refuse to compile if any role is missing.
//
// ZIN-4714 — `helios:tenant:transfer` is OWNER-only by design. Ownership
// transfer is the single entry point to the OWNER role (assignMember and
// createInvitation refuse role: OWNER); it cannot be delegated to ADMIN.
// =============================================================================

// -----------------------------------------------------------------------------
// Permission vocabulary
// -----------------------------------------------------------------------------

const ATHENS_PERMISSIONS = [
  'athens:project:view',
  'athens:project:update',
  'athens:project:delete',
  'athens:services:enable',
  'athens:services:disable',
  'athens:team:invite',
  'athens:team:remove',
] as const;

const MERCURY_PERMISSIONS = [
  'mercury:users:read',
  'mercury:users:write',
  'mercury:api_keys:manage',
  'mercury:connections:read',
] as const;

const MUSE_PERMISSIONS = [
  'muse:posts:read',
  'muse:posts:write',
  'muse:posts:delete',
  'muse:drafts:read',
  'muse:drafts:write',
] as const;

const HELIOS_PERMISSIONS = [
  'helios:members:view',
  'helios:members:invite',
  'helios:members:remove',
  'helios:roles:assign',
  'helios:roles:revoke',
  'helios:invitations:create',
  'helios:invitations:revoke',
  'helios:tenant:switch',
  'helios:tenant:transfer',
] as const;

/**
 * The full set of valid permission strings in the system.
 *
 * The union type is the precise closed set. The `Permission` exported
 * type is used everywhere callers need to gate a decision. Typos get
 * caught at compile time when assigned into ROLE_PERMISSIONS.
 */
export type Permission =
  | (typeof ATHENS_PERMISSIONS)[number]
  | (typeof MERCURY_PERMISSIONS)[number]
  | (typeof MUSE_PERMISSIONS)[number]
  | (typeof HELIOS_PERMISSIONS)[number];

/**
 * The four roles. Mirrors `RoleType` in Helios's Prisma schema. Defined
 * here as a const tuple so the union below is the closed set.
 */
export const ROLES = ['OWNER', 'ADMIN', 'EDITOR', 'VIEWER'] as const;
export type Role = (typeof ROLES)[number];

/**
 * Static role → permission map.
 *
 * Convention:
 *   - OWNER gets everything in every service.
 *   - ADMIN gets everything except destructive `*:delete` and ownership-level
 *     operations (athens:project:delete, muse:posts:delete, helios:tenant:transfer).
 *   - EDITOR gets read + write on content services (muse), but no team or
 *     service-management permissions.
 *   - VIEWER is read-only across all services.
 *
 * `helios:tenant:switch` is granted to every role (OWNER / ADMIN / EDITOR /
 * VIEWER) because switching the active tenant is a navigation gesture, not
 * a privileged operation. It is the platform user model where every member
 * is a platform user; switching just picks which tenant's perms are active.
 */
export const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  OWNER: [
    ...ATHENS_PERMISSIONS,
    ...MERCURY_PERMISSIONS,
    ...MUSE_PERMISSIONS,
    ...HELIOS_PERMISSIONS,
  ],

  ADMIN: [
    // Athens — everything except delete-project and team removal
    'athens:project:view',
    'athens:project:update',
    'athens:services:enable',
    'athens:services:disable',
    'athens:team:invite',
    // Mercury
    'mercury:users:read',
    'mercury:users:write',
    'mercury:api_keys:manage',
    'mercury:connections:read',
    // Muse — everything except post delete
    'muse:posts:read',
    'muse:posts:write',
    'muse:drafts:read',
    'muse:drafts:write',
    // Helios
    'helios:members:view',
    'helios:members:invite',
    'helios:members:remove',
    'helios:roles:assign',
    'helios:roles:revoke',
    'helios:invitations:create',
    'helios:invitations:revoke',
    'helios:tenant:switch',
  ],

  EDITOR: [
    'athens:project:view',
    'mercury:users:read',
    'mercury:connections:read',
    'muse:posts:read',
    'muse:posts:write',
    'muse:drafts:read',
    'muse:drafts:write',
    'helios:members:view',
    'helios:tenant:switch',
  ],

  VIEWER: [
    'athens:project:view',
    'mercury:users:read',
    'mercury:connections:read',
    'muse:posts:read',
    'muse:drafts:read',
    'helios:members:view',
    'helios:tenant:switch',
  ],
} as const;

/**
 * Returns the read-only permission array for a role.
 *
 * The array is `readonly` so callers cannot accidentally mutate the
 * shared map. Spread it (`[...resolvePermissions(role)]`) if you need
 * a mutable copy.
 */
export function resolvePermissions(role: Role): readonly Permission[] {
  return ROLE_PERMISSIONS[role];
}

/**
 * `true` if `role` is granted `perm`. Convenience wrapper around
 * `ROLE_PERMISSIONS[role].includes(perm)`. Used by Helios's
 * PermissionResolverService when resolving per-tenant membership rows.
 */
export function roleHasPermission(role: Role, perm: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(perm);
}

/**
 * Type guard: returns `true` if `value` is a known Permission string.
 * Use at trust boundaries (HTTP request bodies, Kafka payloads) where
 * the perm may be an arbitrary string and we want to reject unknowns
 * rather than silently return false.
 */
export function isPermission(value: unknown): value is Permission {
  if (typeof value !== 'string') return false;
  // The closed union check: every Permission is one of these strings.
  return (
    (ATHENS_PERMISSIONS as readonly string[]).includes(value) ||
    (MERCURY_PERMISSIONS as readonly string[]).includes(value) ||
    (MUSE_PERMISSIONS as readonly string[]).includes(value) ||
    (HELIOS_PERMISSIONS as readonly string[]).includes(value)
  );
}

/**
 * Type guard: returns `true` if `value` is a known Role string.
 */
export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (ROLES as readonly string[]).includes(value);
}

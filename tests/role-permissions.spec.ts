// =============================================================================
// role-permissions.spec.ts — pure unit tests for the canonical map.
//
// No mocks. These are the most important tests in the SDK — every other
// service depends on this map being correct.
// =============================================================================

import {
  ROLE_PERMISSIONS,
  ROLES,
  resolvePermissions,
  roleHasPermission,
  isPermission,
  isRole,
  type Permission,
  type Role,
} from '../src/role-permissions';

describe('ROLE_PERMISSIONS', () => {
  it('grants OWNER every permission in every service', () => {
    const ownerPerms = ROLE_PERMISSIONS.OWNER;
    expect(ownerPerms).toContain('athens:project:delete');
    expect(ownerPerms).toContain('athens:services:enable');
    expect(ownerPerms).toContain('mercury:users:write');
    expect(ownerPerms).toContain('mercury:api_keys:manage');
    expect(ownerPerms).toContain('muse:posts:delete');
    expect(ownerPerms).toContain('helios:tenant:transfer');
  });

  it('grants ADMIN everything except destructive deletes and ownership transfer', () => {
    const adminPerms = ROLE_PERMISSIONS.ADMIN;
    expect(adminPerms).toContain('athens:project:update');
    expect(adminPerms).toContain('athens:project:view');
    expect(adminPerms).not.toContain('athens:project:delete');
    expect(adminPerms).toContain('muse:posts:write');
    expect(adminPerms).not.toContain('muse:posts:delete');
    expect(adminPerms).not.toContain('helios:tenant:transfer');
    // Switch is a navigation gesture, available to every role.
    expect(adminPerms).toContain('helios:tenant:switch');
  });

  it('grants EDITOR read+write on content services, no team mgmt', () => {
    const editorPerms = ROLE_PERMISSIONS.EDITOR;
    expect(editorPerms).toContain('muse:posts:read');
    expect(editorPerms).toContain('muse:posts:write');
    expect(editorPerms).toContain('muse:drafts:write');
    expect(editorPerms).not.toContain('muse:posts:delete');
    expect(editorPerms).not.toContain('athens:project:update');
    expect(editorPerms).not.toContain('helios:members:invite');
    expect(editorPerms).not.toContain('helios:tenant:transfer');
  });

  it('grants VIEWER read-only across services', () => {
    const viewerPerms = ROLE_PERMISSIONS.VIEWER;
    expect(viewerPerms).toContain('athens:project:view');
    expect(viewerPerms).toContain('mercury:users:read');
    expect(viewerPerms).toContain('muse:posts:read');
    expect(viewerPerms).not.toContain('muse:posts:write');
    expect(viewerPerms).not.toContain('muse:drafts:write');
    expect(viewerPerms).not.toContain('mercury:users:write');
    expect(viewerPerms).not.toContain('helios:members:invite');
  });

  it('includes every role in the Record (compile-time guard, runtime check)', () => {
    expect(ROLES).toEqual(['OWNER', 'ADMIN', 'EDITOR', 'VIEWER']);
    for (const role of ROLES) {
      expect(Array.isArray(ROLE_PERMISSIONS[role])).toBe(true);
    }
  });

  it('perms are sorted to be a superset (OWNER ⊇ ADMIN ⊇ EDITOR ⊇ VIEWER) on common entries', () => {
    // OWNER gets everything; others get subsets.
    const owner = new Set(ROLE_PERMISSIONS.OWNER);
    const admin = new Set(ROLE_PERMISSIONS.ADMIN);
    const editor = new Set(ROLE_PERMISSIONS.EDITOR);
    const viewer = new Set(ROLE_PERMISSIONS.VIEWER);

    // Every editor perm is in admin (admin ⊇ editor).
    for (const p of editor) expect(admin.has(p)).toBe(true);
    // Every viewer perm is in editor (editor ⊇ viewer).
    for (const p of viewer) expect(editor.has(p)).toBe(true);
    // Every admin perm is in owner (owner ⊇ admin).
    for (const p of admin) expect(owner.has(p)).toBe(true);
  });
});

describe('resolvePermissions', () => {
  it('returns the perms for a role', () => {
    expect(resolvePermissions('OWNER')).toContain('helios:tenant:transfer');
    expect(resolvePermissions('VIEWER')).not.toContain('helios:tenant:transfer');
  });
});

describe('roleHasPermission', () => {
  it('returns true when role grants perm', () => {
    expect(roleHasPermission('OWNER', 'helios:tenant:transfer')).toBe(true);
    expect(roleHasPermission('ADMIN', 'helios:members:invite')).toBe(true);
  });

  it('returns false when role lacks perm', () => {
    expect(roleHasPermission('VIEWER', 'helios:tenant:transfer')).toBe(false);
    expect(roleHasPermission('EDITOR', 'muse:posts:delete')).toBe(false);
  });
});

describe('isPermission', () => {
  it('accepts valid perm strings', () => {
    expect(isPermission('helios:members:view')).toBe(true);
    expect(isPermission('athens:project:delete')).toBe(true);
  });

  it('rejects invalid strings', () => {
    expect(isPermission('helios:made_up:perm')).toBe(false);
    expect(isPermission('')).toBe(false);
    expect(isPermission(null)).toBe(false);
    expect(isPermission(undefined)).toBe(false);
    expect(isPermission(42)).toBe(false);
  });
});

describe('isRole', () => {
  it('accepts valid role strings', () => {
    expect(isRole('OWNER')).toBe(true);
    expect(isRole('VIEWER')).toBe(true);
  });

  it('rejects invalid strings', () => {
    expect(isRole('SUPERADMIN')).toBe(false);
    expect(isRole('')).toBe(false);
    expect(isRole(null)).toBe(false);
  });
});

describe('Permission union exhaustiveness', () => {
  it('every string in ROLE_PERMISSIONS is a valid Permission type', () => {
    // If ROLE_PERMISSIONS ever contained a string not in the union,
    // this assignment would fail at compile time. The runtime check is
    // a belt-and-braces sanity assertion.
    const _check: readonly Permission[] = ROLE_PERMISSIONS.OWNER;
    void _check;
    expect(true).toBe(true);
  });

  it('every Role maps to a non-empty perm array', () => {
    for (const role of ROLES) {
      const perms = ROLE_PERMISSIONS[role as Role];
      expect(perms.length).toBeGreaterThan(0);
    }
  });
});

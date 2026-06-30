// =============================================================================
// role-permissions.spec.ts — pure unit tests for the canonical map.
//
// No mocks. These are the most important tests in the SDK — every other
// service depends on this map being correct.
//
// v1.3.0: perms are partitioned by `scope` (self / platform / project /
// platform/project). SELF perms are universal (granted by the resolver's
// Step 1, not in any role). PROJECT perms are tenant-user only (granted
// via TenantRole, not in any role). Only PLATFORM and PLATFORM/PROJECT
// perms appear in ROLE_PERMISSIONS.
// =============================================================================

import {
  ROLE_PERMISSIONS,
  ROLES,
  resolvePermissions,
  roleHasPermission,
  isPermission,
  isRole,
  isSelfScope,
  isPlatformGrantable,
  isTenantGrantable,
  PERM_SCOPE,
  SELF_PERMISSIONS,
  PLATFORM_PERMISSIONS,
  PROJECT_PERMISSIONS,
  DUAL_PERMISSIONS,
  type Permission,
  type Role,
  type PermScope,
} from '../src/role-permissions';

describe('ROLE_PERMISSIONS', () => {
  it('grants OWNER every platform + dual-scope perm in the contract', () => {
    const ownerPerms = ROLE_PERMISSIONS.OWNER;
    // Platform-scope perms
    expect(ownerPerms).toContain('athens:project:delete');
    expect(ownerPerms).toContain('athens:services:enable');
    expect(ownerPerms).toContain('mercury:users:write');
    // v1.5.0: api_keys:manage remains OWNER-only (deprecated umbrella)
    expect(ownerPerms).toContain('mercury:api_keys:manage');
    // v1.5.0: split-out api_keys perms — OWNER gets all four
    expect(ownerPerms).toContain('mercury:api_keys:create');
    expect(ownerPerms).toContain('mercury:api_keys:revoke');
    expect(ownerPerms).toContain('mercury:api_keys:read');
    expect(ownerPerms).toContain('muse:author:delete');
    expect(ownerPerms).toContain('helios:tenant:transfer');
    // Dual-scope perms (valid in platform-user path too)
    expect(ownerPerms).toContain('muse:author:read');
    // v1.5.0: new Mercury platform-scope perms all flow to OWNER
    expect(ownerPerms).toContain('mercury:users:batch_read');
    expect(ownerPerms).toContain('mercury:service_clients:read');
    expect(ownerPerms).toContain('mercury:auth_config:read');
    expect(ownerPerms).toContain('mercury:auth_config_apple:create');
    expect(ownerPerms).toContain('mercury:auth_config_oauth:update');
    expect(ownerPerms).toContain('mercury:auth_config_forgot_password:create');
    expect(ownerPerms).toContain('mercury:connection_oauth:refresh');
    expect(ownerPerms).toContain('mercury:events:consume');
  });

  it('grants ADMIN everything except destructive deletes and ownership transfer', () => {
    const adminPerms = ROLE_PERMISSIONS.ADMIN;
    expect(adminPerms).toContain('athens:project:update');
    expect(adminPerms).toContain('athens:project:view');
    expect(adminPerms).not.toContain('athens:project:delete');
    expect(adminPerms).toContain('muse:blog:create');
    expect(adminPerms).toContain('muse:author:create');
    expect(adminPerms).not.toContain('muse:author:delete');
    expect(adminPerms).not.toContain('helios:tenant:transfer');
    // v1.5.0: ADMIN gets the split api_keys perms but NOT the deprecated
    // api_keys:manage umbrella (OWNER-only).
    expect(adminPerms).toContain('mercury:api_keys:create');
    expect(adminPerms).toContain('mercury:api_keys:revoke');
    expect(adminPerms).toContain('mercury:api_keys:read');
    expect(adminPerms).not.toContain('mercury:api_keys:manage');
    // v1.5.0: new Mercury platform-scope perms flow to ADMIN too
    // (users:batch_read stays OWNER-only — bulk read is sensitive)
    expect(adminPerms).not.toContain('mercury:users:batch_read');
    expect(adminPerms).toContain('mercury:service_clients:read');
    expect(adminPerms).toContain('mercury:auth_config:read');
    expect(adminPerms).toContain('mercury:events:consume');
  });

  it('grants EDITOR platform-user read/write on content services, no team mgmt', () => {
    const editorPerms = ROLE_PERMISSIONS.EDITOR;
    expect(editorPerms).toContain('muse:blog:create');
    expect(editorPerms).toContain('muse:blog:read');
    expect(editorPerms).toContain('muse:author:create');
    expect(editorPerms).not.toContain('muse:author:delete');
    expect(editorPerms).not.toContain('athens:project:update');
    expect(editorPerms).not.toContain('helios:members:invite');
    expect(editorPerms).not.toContain('helios:tenant:transfer');
  });

  it('grants VIEWER read-only across services', () => {
    const viewerPerms = ROLE_PERMISSIONS.VIEWER;
    expect(viewerPerms).toContain('athens:project:view');
    expect(viewerPerms).toContain('mercury:users:read');
    expect(viewerPerms).toContain('muse:blog:read');
    expect(viewerPerms).toContain('muse:author:read');
    expect(viewerPerms).not.toContain('muse:blog:create');
    expect(viewerPerms).not.toContain('muse:author:create');
    expect(viewerPerms).not.toContain('mercury:users:write');
    expect(viewerPerms).not.toContain('helios:members:invite');
  });

  it('never includes self-scope perms (universal — granted by resolver Step 1)', () => {
    for (const role of ROLES) {
      for (const perm of ROLE_PERMISSIONS[role]) {
        expect(isSelfScope(perm as Permission)).toBe(false);
      }
    }
  });

  it('never includes project-scope perms (tenant-user — granted via TenantRole)', () => {
    for (const role of ROLES) {
      for (const perm of ROLE_PERMISSIONS[role]) {
        expect(PERM_SCOPE[perm as Permission]).not.toBe('project');
      }
    }
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
    expect(roleHasPermission('EDITOR', 'muse:author:delete')).toBe(false);
  });
});

describe('isPermission', () => {
  it('accepts valid perm strings', () => {
    expect(isPermission('helios:members:view')).toBe(true);
    expect(isPermission('athens:project:delete')).toBe(true);
    expect(isPermission('helios:tenant:switch:self')).toBe(true); // self-scope
    expect(isPermission('muse:posts:read')).toBe(true); // project-scope
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

// =============================================================================
// v1.3.0 — 4-scope model
// =============================================================================

describe('PERM_SCOPE (v1.3.0 / v1.5.0)', () => {
  it('contains every perm in the contract vocabulary', () => {
    // v1.5.0 (ZIN-4902): contract has 58 perms (12 self + 40 platform + 5
    // project + 1 dual = 58; 29 Mercury + 7 Athens + 10 Muse + 12 Helios).
    // v1.3.0 had 31 perms; v1.4.0 added 3 helios:external:* perms (34);
    // v1.5.0 adds 24 Mercury perms. Every one of them MUST appear in
    // PERM_SCOPE.
    expect(PERM_SCOPE['helios:tenant:switch:self']).toBe('self');
    expect(PERM_SCOPE['mercury:user:read:self']).toBe('self');
    expect(PERM_SCOPE['mercury:user:write:self']).toBe('self');
    expect(PERM_SCOPE['mercury:user:delete:self']).toBe('self'); // v1.5.0
    expect(PERM_SCOPE['mercury:connection:read:self']).toBe('self'); // v1.5.0
    expect(PERM_SCOPE['mercury:connection_slack:revoke:self']).toBe('self'); // v1.5.0

    expect(PERM_SCOPE['athens:project:view']).toBe('platform');
    expect(PERM_SCOPE['helios:tenant:transfer']).toBe('platform');
    // v1.5.0: split api_keys:manage into create/revoke/read; manage is
    // OWNER-only deprecated umbrella.
    expect(PERM_SCOPE['mercury:api_keys:create']).toBe('platform');
    expect(PERM_SCOPE['mercury:api_keys:revoke']).toBe('platform');
    expect(PERM_SCOPE['mercury:api_keys:read']).toBe('platform');
    expect(PERM_SCOPE['mercury:api_keys:manage']).toBe('platform');
    // v1.5.0: new platform-scope mercury perms
    expect(PERM_SCOPE['mercury:users:batch_read']).toBe('platform');
    expect(PERM_SCOPE['mercury:service_clients:read']).toBe('platform');
    expect(PERM_SCOPE['mercury:events:consume']).toBe('platform');
    expect(PERM_SCOPE['mercury:auth_config:read']).toBe('platform');
    expect(PERM_SCOPE['mercury:auth_config_apple:create']).toBe('platform');
    expect(PERM_SCOPE['mercury:connection_oauth:refresh']).toBe('platform');

    expect(PERM_SCOPE['muse:posts:read']).toBe('project');
    expect(PERM_SCOPE['muse:drafts:write']).toBe('project');

    expect(PERM_SCOPE['muse:author:read']).toBe('platform/project');
  });

  it('has 4 valid scope values (one of: self, platform, project, platform/project)', () => {
    const valid: PermScope[] = ['self', 'platform', 'project', 'platform/project'];
    for (const scope of Object.values(PERM_SCOPE)) {
      expect(valid).toContain(scope);
    }
  });
});

describe('scope-partitioned tuples (v1.3.0)', () => {
  it('v1.5.0 scope counts: 12 self, 40 platform, 5 project, 1 dual (= 58 total)', () => {
    // Locks the 4-segment-allowed v1.5.0 schema. If the contract grows
    // or the emitter starts bucketing incorrectly, this fails first.
    expect(SELF_PERMISSIONS).toHaveLength(12);
    expect(PLATFORM_PERMISSIONS).toHaveLength(40);
    expect(PROJECT_PERMISSIONS).toHaveLength(5);
    expect(DUAL_PERMISSIONS).toHaveLength(1);
    expect(Object.keys(PERM_SCOPE)).toHaveLength(58);
    expect(
      SELF_PERMISSIONS.length +
        PLATFORM_PERMISSIONS.length +
        PROJECT_PERMISSIONS.length +
        DUAL_PERMISSIONS.length,
    ).toBe(Object.keys(PERM_SCOPE).length);
  });

  it('SELF_PERMISSIONS only contains self-scope perms', () => {
    for (const p of SELF_PERMISSIONS) {
      expect(PERM_SCOPE[p as Permission]).toBe('self');
    }
    expect(SELF_PERMISSIONS).toContain('helios:tenant:switch:self');
    expect(SELF_PERMISSIONS).toContain('mercury:user:read:self');
    // v1.5.0: new self-scope Mercury perms
    expect(SELF_PERMISSIONS).toContain('mercury:user:delete:self');
    expect(SELF_PERMISSIONS).toContain('mercury:connection:read:self');
    expect(SELF_PERMISSIONS).toContain('mercury:connection_slack:revoke:self');
    expect(SELF_PERMISSIONS).toContain('mercury:connection_google:revoke:self');
    expect(SELF_PERMISSIONS).toContain('mercury:connection_imap:revoke:self');
    expect(SELF_PERMISSIONS).toContain('mercury:connection_imap:create:self');
    expect(SELF_PERMISSIONS).toContain('mercury:connection_slack:phrase_create:self');
    expect(SELF_PERMISSIONS).toContain('mercury:connection_oauth:initiate:self');
    expect(SELF_PERMISSIONS).toContain('mercury:connection_oauth:complete:self');
  });

  it('PLATFORM_PERMISSIONS only contains platform-scope perms', () => {
    for (const p of PLATFORM_PERMISSIONS) {
      expect(PERM_SCOPE[p as Permission]).toBe('platform');
    }
    // v1.5.0 spot-checks
    expect(PLATFORM_PERMISSIONS).toContain('mercury:api_keys:create');
    expect(PLATFORM_PERMISSIONS).toContain('mercury:api_keys:revoke');
    expect(PLATFORM_PERMISSIONS).toContain('mercury:api_keys:read');
    expect(PLATFORM_PERMISSIONS).toContain('mercury:api_keys:manage');
    expect(PLATFORM_PERMISSIONS).toContain('mercury:users:batch_read');
    expect(PLATFORM_PERMISSIONS).toContain('mercury:service_clients:read');
    expect(PLATFORM_PERMISSIONS).toContain('mercury:events:consume');
    expect(PLATFORM_PERMISSIONS).toContain('mercury:auth_config:read');
    expect(PLATFORM_PERMISSIONS).toContain('mercury:connection_oauth:refresh');
  });

  it('PROJECT_PERMISSIONS only contains project-scope perms', () => {
    for (const p of PROJECT_PERMISSIONS) {
      expect(PERM_SCOPE[p as Permission]).toBe('project');
    }
    expect(PROJECT_PERMISSIONS).toContain('muse:posts:read');
    expect(PROJECT_PERMISSIONS).toContain('muse:drafts:write');
  });

  it('DUAL_PERMISSIONS only contains platform/project-scope perms', () => {
    for (const p of DUAL_PERMISSIONS) {
      expect(PERM_SCOPE[p as Permission]).toBe('platform/project');
    }
  });

  it('every contract perm appears in exactly one tuple (union covers the vocabulary)', () => {
    const allFromTuples = new Set<Permission>([
      ...SELF_PERMISSIONS,
      ...PLATFORM_PERMISSIONS,
      ...PROJECT_PERMISSIONS,
      ...DUAL_PERMISSIONS,
    ]);
    // Every key in PERM_SCOPE is in the tuple union.
    for (const name of Object.keys(PERM_SCOPE) as Permission[]) {
      expect(allFromTuples.has(name)).toBe(true);
    }
    // And no name is duplicated across tuples.
    const seen = new Set<Permission>();
    for (const p of allFromTuples) {
      expect(seen.has(p)).toBe(false);
      seen.add(p);
    }
  });
});

describe('isSelfScope', () => {
  it('returns true for self-scope perms', () => {
    expect(isSelfScope('helios:tenant:switch:self' as Permission)).toBe(true);
    expect(isSelfScope('mercury:user:read:self' as Permission)).toBe(true);
  });

  it('returns false for non-self-scope perms', () => {
    expect(isSelfScope('athens:project:view' as Permission)).toBe(false);
    expect(isSelfScope('muse:posts:read' as Permission)).toBe(false);
    expect(isSelfScope('muse:author:read' as Permission)).toBe(false);
  });
});

describe('isPlatformGrantable', () => {
  it('returns true for platform-scope perms', () => {
    expect(isPlatformGrantable('athens:project:view' as Permission)).toBe(true);
    expect(isPlatformGrantable('helios:tenant:transfer' as Permission)).toBe(true);
  });

  it('returns true for platform/project (dual) perms', () => {
    expect(isPlatformGrantable('muse:author:read' as Permission)).toBe(true);
  });

  it('returns false for self-scope perms (universal — not via ROLE_PERMISSIONS)', () => {
    expect(isPlatformGrantable('helios:tenant:switch:self' as Permission)).toBe(false);
    expect(isPlatformGrantable('mercury:user:read:self' as Permission)).toBe(false);
  });

  it('returns false for project-scope perms (tenant-user only)', () => {
    expect(isPlatformGrantable('muse:posts:read' as Permission)).toBe(false);
    expect(isPlatformGrantable('muse:drafts:write' as Permission)).toBe(false);
  });
});

describe('isTenantGrantable', () => {
  it('returns true for project-scope perms', () => {
    expect(isTenantGrantable('muse:posts:read' as Permission)).toBe(true);
    expect(isTenantGrantable('muse:posts:delete' as Permission)).toBe(true);
  });

  it('returns true for platform/project (dual) perms', () => {
    expect(isTenantGrantable('muse:author:read' as Permission)).toBe(true);
  });

  it('returns false for self-scope perms (universal — not via TenantRole)', () => {
    expect(isTenantGrantable('helios:tenant:switch:self' as Permission)).toBe(false);
  });

  it('returns false for platform-only perms (not grantable via TenantRole)', () => {
    expect(isTenantGrantable('athens:project:view' as Permission)).toBe(false);
    expect(isTenantGrantable('helios:tenant:transfer' as Permission)).toBe(false);
  });

  it('returns true for unknown perms (tenant-defined — default to tenant grantable)', () => {
    // Tenant-defined perms (e.g. `inventory:items:read`) are not in the
    // contract vocabulary. The resolver treats them as tenant-user-only.
    expect(isTenantGrantable('inventory:items:read')).toBe(true);
    expect(isTenantGrantable('custom_tenant_perm:foo:bar')).toBe(true);
  });
});
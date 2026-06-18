// =============================================================================
// @wazobiatech/helios-permissions — public API barrel.
//
// Re-exports the canonical role → permission map (the platform source
// of truth), the PermissionClient (the authz decision surface), the
// cache abstractions, and the NestJS bindings.
//
// Importers:
//
//   // Hot-path authz decision in any service:
//   import { PermissionClient } from '@wazobiatech/helios-permissions';
//   const granted = await perms.callerHasPermission(userId, tenantId, 'helios:members:update');
//
//   // NestJS module wiring:
//   import { PermissionsModule, PERMISSION_CLIENT } from '@wazobiatech/helios-permissions/nestjs';
//
//   // Pure data — used by Helios itself to compute perms from roles:
//   import { ROLE_PERMISSIONS, resolvePermissions } from '@wazobiatech/helios-permissions/role-permissions';
// =============================================================================

export {
  ROLE_PERMISSIONS,
  ROLES,
  resolvePermissions,
  roleHasPermission,
  isPermission,
  isRole,
} from './role-permissions';
export type { Permission, Role } from './role-permissions';

export { PermissionClient } from './permission-client';
export type {
  PermissionClientOptions,
  PermissionExplanation,
} from './permission-client';

export { createPermissionClient } from './factory';
export type {
  CreatePermissionClientOptions,
  CreatePermissionClientResult,
} from './factory';

export type { Logger } from './types/logger';
export { silentLogger, consoleLogger } from './types/logger';

export { HeliosClient, HeliosUnreachableError } from './helios/fetch-user-permissions';
export type {
  HeliosClientOptions,
  HeliosMembershipResolution,
} from './helios/fetch-user-permissions';

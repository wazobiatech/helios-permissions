// =============================================================================
// RequirePermission — convenience guard for NestJS resolvers/handlers.
//
// Most service-layer code calls `permissionClient.callerHasPermission(...)`
// directly (per-tenant check). RequirePermission is for the rare case
// where you want a one-liner guard at the resolver boundary and don't
// need to inspect the perm list yourself.
//
// IMPORTANT: RequirePermission takes (tenantId, perm). The tenantId is
// expected to be on the request body / args — the decorator does NOT
// guess. If your resolver doesn't have tenantId in args, use
// `permissionClient.callerHasPermission(...)` directly with explicit args.
//
// Usage:
//   @UseGuards(JwtAuthGuard, RequirePermissionGuard)
//   @RequirePermission('input.tenantId', 'helios:members:update')
//   @Mutation(() => Boolean)
//   async changeRole(...) { ... }
// =============================================================================

import { Inject, type CanActivate, type ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { PERMISSION_CLIENT } from './permissions.module';
import { PermissionClient } from '../permission-client';
import type { Permission } from '../role-permissions';

export const REQUIRE_PERMISSION_KEY = 'helios-permissions:require-permission';

/**
 * Marks a route with the required tenantId path + permission string.
 *
 * `tenantIdPath` is a dot-path into the GraphQL args / REST body, e.g.
 * `'input.tenantId'` or `'params.tenantId'`. The guard resolves it at
 * request time.
 */
export function RequirePermission(
  tenantIdPath: string,
  perm: Permission,
): MethodDecorator {
  return (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor,
  ): PropertyDescriptor => {
    const metadata = { tenantIdPath, perm };
    Reflect.defineMetadata(REQUIRE_PERMISSION_KEY, metadata, descriptor.value);
    Reflect.defineMetadata(REQUIRE_PERMISSION_KEY, metadata, target, propertyKey);
    return descriptor;
  };
}

@Injectable()
export class RequirePermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(PERMISSION_CLIENT) private readonly perms: PermissionClient,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const meta = this.reflector.get<{ tenantIdPath: string; perm: Permission } | undefined>(
      REQUIRE_PERMISSION_KEY,
      context.getHandler(),
    );
    if (meta === undefined) return true; // No @RequirePermission on this route.

    const req = context.switchToHttp().getRequest();
    const args = req.body ?? req.query ?? {};

    // Resolve tenantId from the dot-path. Simple traversal — production
    // callers use `input.tenantId` (GraphQL) or `params.tenantId` (REST).
    const tenantId = this.resolvePath(args, meta.tenantIdPath);
    if (typeof tenantId !== 'string' || tenantId.length === 0) {
      return false;
    }

    const actor = req.user?.uuid;
    if (typeof actor !== 'string' || actor.length === 0) {
      return false;
    }

    return this.perms.callerHasPermission(actor, tenantId, meta.perm);
  }

  private resolvePath(obj: Record<string, unknown>, path: string): unknown {
    const parts = path.split('.');
    let cur: unknown = obj;
    for (const part of parts) {
      if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
      cur = (cur as Record<string, unknown>)[part];
    }
    return cur;
  }
}

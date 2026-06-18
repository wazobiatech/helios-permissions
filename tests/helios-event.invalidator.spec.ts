// =============================================================================
// helios-event.invalidator.spec.ts — exercise the four event handlers.
//
// Uses a stub PermissionClient that records calls instead of touching
// Redis. The transport-agnostic handler methods are what we test —
// callers wire their own Kafka / Hecate consumer.
// =============================================================================

import { HeliosEventInvalidator } from '../src/nestjs/consumers/helios-event.invalidator';
import type { PermissionClient } from '../src/permission-client';

class StubPermissionClient {
  public invalidations: Array<{ userId: string; tenantId?: string }> = [];
  public tenantInvalidations: string[] = [];

  async invalidate(userId: string, tenantId?: string): Promise<void> {
    this.invalidations.push({ userId, tenantId });
  }

  async invalidateTenant(tenantId: string): Promise<void> {
    this.tenantInvalidations.push(tenantId);
  }

  // Unused in this spec but required for the type.
  async callerHasPermission(): Promise<boolean> {
    return false;
  }
  async getUserPermissions(): Promise<never[]> {
    return [];
  }
  async explain(): Promise<never> {
    throw new Error('not used');
  }
  async writeThrough(): Promise<void> {
    // no-op
  }
}

const silentLogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

describe('HeliosEventInvalidator', () => {
  let stub: StubPermissionClient;
  let invalidator: HeliosEventInvalidator;

  beforeEach(() => {
    stub = new StubPermissionClient();
    invalidator = new HeliosEventInvalidator(stub as unknown as PermissionClient, silentLogger);
  });

  describe('onMemberRemoved', () => {
    it('invalidates all entries for the removed user', async () => {
      await invalidator.onMemberRemoved({
        name: 'helios.member.removed',
        payload: { tenantId: 't-1', userId: 'u-1' },
      });
      expect(stub.invalidations).toEqual([{ userId: 'u-1', tenantId: undefined }]);
    });

    it('no-ops gracefully on missing payload', async () => {
      await invalidator.onMemberRemoved({ name: 'helios.member.removed', payload: undefined as never });
      expect(stub.invalidations).toEqual([]);
    });
  });

  describe('onRoleChanged', () => {
    it('invalidates the specific (userId, tenantId) entry', async () => {
      await invalidator.onRoleChanged({
        name: 'helios.role.changed',
        payload: { tenantId: 't-1', userId: 'u-1' },
      });
      expect(stub.invalidations).toEqual([{ userId: 'u-1', tenantId: 't-1' }]);
    });

    it('no-ops gracefully on missing userId', async () => {
      await invalidator.onRoleChanged({
        name: 'helios.role.changed',
        payload: { tenantId: 't-1' } as never,
      });
      expect(stub.invalidations).toEqual([]);
    });
  });

  describe('onInvitationAccepted', () => {
    it('invalidates the (userId, tenantId) entry so the new role is reflected', async () => {
      await invalidator.onInvitationAccepted({
        name: 'helios.invitation.accepted',
        payload: { tenantId: 't-1', userId: 'u-1' },
      });
      expect(stub.invalidations).toEqual([{ userId: 'u-1', tenantId: 't-1' }]);
    });
  });

  describe('onOwnershipTransferred', () => {
    it('invalidates both previous and new owner entries for the tenant', async () => {
      await invalidator.onOwnershipTransferred({
        name: 'helios.ownership.transferred',
        payload: { tenantId: 't-1', previousOwnerUserId: 'u-prev', newOwnerUserId: 'u-new' },
      });
      expect(stub.invalidations).toEqual([
        { userId: 'u-prev', tenantId: 't-1' },
        { userId: 'u-new', tenantId: 't-1' },
      ]);
    });

    it('no-ops gracefully on missing fields', async () => {
      await invalidator.onOwnershipTransferred({
        name: 'helios.ownership.transferred',
        payload: { tenantId: 't-1' } as never,
      });
      expect(stub.invalidations).toEqual([]);
    });
  });
});

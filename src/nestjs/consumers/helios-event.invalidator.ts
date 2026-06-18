// =============================================================================
// HeliosEventInvalidator — defense-in-depth cache invalidator.
//
// Helios writes to the cache synchronously after every perm change (the
// write-through path). Kafka events are emitted as a backup for any
// downstream service that might cache locally or for any case where
// Helios's sync write didn't complete (Redis blip, process crash, etc.).
//
// Wires four event handlers, one per Helios event that affects perms:
//   - helios.member.removed       → invalidate(userId)
//   - helios.role.changed         → invalidate(userId, tenantId)
//   - helios.invitation.accepted  → invalidate(userId, tenantId)
//   - helios.ownership.transferred → invalidate(prevOwner, tenantId) +
//                                   invalidate(newOwner, tenantId)
//
// Event payload shape mirrors the Helios event registry in
// `wazobiatech/helios/schemas/event/helios.json`. We accept unknown
// fields gracefully — the SDK only reads what it needs.
// =============================================================================

import { Inject, Injectable } from '@nestjs/common';

import { PERMISSION_CLIENT } from '../permissions.module';
import { PermissionClient } from '../../permission-client';
import type { Logger } from '../../types/logger';
import { silentLogger } from '../../types/logger';

export interface PlatformEvent<T = unknown> {
  name: string;
  actor?: string;
  payload: T;
}

@Injectable()
export class HeliosEventInvalidator {
  private readonly logger: Logger;

  constructor(
    @Inject(PERMISSION_CLIENT) private readonly perms: PermissionClient,
    logger?: Logger,
  ) {
    this.logger = logger ?? silentLogger;
  }

  /**
   * Wire all four event handlers. Callers bind the methods to their own
   * Kafka / Hecate consumer module — the SDK doesn't bind to a specific
   * transport. Example:
   *
   *   const invalidator = new HeliosEventInvalidator(perms);
   *   kafkaConsumer.on('helios.member.removed', (e) => invalidator.onMemberRemoved(e));
   *   kafkaConsumer.on('helios.role.changed', (e) => invalidator.onRoleChanged(e));
   *   kafkaConsumer.on('helios.invitation.accepted', (e) => invalidator.onInvitationAccepted(e));
   *   kafkaConsumer.on('helios.ownership.transferred', (e) => invalidator.onOwnershipTransferred(e));
   */

  async onMemberRemoved(event: PlatformEvent<{ tenantId: string; userId: string }>): Promise<void> {
    const payload = event.payload;
    const userId = (payload as { userId?: unknown })?.userId;
    if (typeof userId !== 'string' || userId.length === 0) return;
    this.logger.info({ event: 'helios.member.removed', userId }, 'Invalidating all perm cache entries for user');
    await this.perms.invalidate(userId);
  }

  async onRoleChanged(event: PlatformEvent<{ tenantId: string; userId: string }>): Promise<void> {
    const payload = event.payload;
    const userId = (payload as { userId?: unknown })?.userId;
    const tenantId = (payload as { tenantId?: unknown })?.tenantId;
    if (typeof userId !== 'string' || typeof tenantId !== 'string') return;
    this.logger.info({ event: 'helios.role.changed', userId, tenantId }, 'Invalidating (userId, tenantId) perm cache');
    await this.perms.invalidate(userId, tenantId);
  }

  async onInvitationAccepted(
    event: PlatformEvent<{ tenantId: string; userId: string }>,
  ): Promise<void> {
    const payload = event.payload;
    const userId = (payload as { userId?: unknown })?.userId;
    const tenantId = (payload as { tenantId?: unknown })?.tenantId;
    if (typeof userId !== 'string' || typeof tenantId !== 'string') return;
    this.logger.info(
      { event: 'helios.invitation.accepted', userId, tenantId },
      'Invalidating (userId, tenantId) perm cache after invitation acceptance',
    );
    await this.perms.invalidate(userId, tenantId);
  }

  async onOwnershipTransferred(
    event: PlatformEvent<{
      tenantId: string;
      previousOwnerUserId: string;
      newOwnerUserId: string;
    }>,
  ): Promise<void> {
    const payload = event.payload;
    const tenantId = (payload as { tenantId?: unknown })?.tenantId;
    const previousOwnerUserId = (payload as { previousOwnerUserId?: unknown })?.previousOwnerUserId;
    const newOwnerUserId = (payload as { newOwnerUserId?: unknown })?.newOwnerUserId;
    if (
      typeof tenantId !== 'string' ||
      typeof previousOwnerUserId !== 'string' ||
      typeof newOwnerUserId !== 'string'
    ) {
      return;
    }
    this.logger.info(
      { event: 'helios.ownership.transferred', tenantId, previousOwnerUserId, newOwnerUserId },
      'Invalidating perm cache for both previous and new owner',
    );
    await Promise.all([
      this.perms.invalidate(previousOwnerUserId, tenantId),
      this.perms.invalidate(newOwnerUserId, tenantId),
    ]);
  }
}

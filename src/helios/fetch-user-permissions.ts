// =============================================================================
// HeliosClient — HMAC-signed GET to Helios's permission endpoint.
//
// Helios exposes:
//   GET /internal/users/:userId/permissions?tenantId=<uuid>
//   Headers: x-project-token, x-source-service, x-signature, x-timestamp
//   Window: 300 seconds (per Helios CLAUDE.md — 300s HMAC for the user
//            endpoints, vs 30s for the events endpoint)
//
// Response shape (matches Helios's PermissionResolverService):
//   { status: 'active', role: 'OWNER', permissions: ['helios:...', ...] }
//   { status: 'inactive', role: 'OWNER' }                          // expired
//   { status: 'not_a_member' }
//
// The SDK translates this into a Permission[] (empty array for non-members
// or inactive memberships — the service-layer callerHasPermission then
// returns false for any perm against an empty array).
//
// HMAC payload (per wazobiatech/nexus-mcp-contract):
//   payload = METHOD.upper() + fullPath + timestamp
//   digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
//   reject if |now - timestamp| > 300s
//
// We implement the signing here directly (instead of pulling in
// @wazobiatech/nexus-mcp) to keep the SDK's dependency surface minimal.
// The signing logic is 10 lines of stdlib code; coupling to the HTTP
// middleware library would be overkill for a single GET.
// =============================================================================

import { createHmac, randomUUID } from 'node:crypto';

import type { Permission } from '../role-permissions';

const HMAC_WINDOW_SECONDS = 300;

export interface HeliosClientOptions {
  /** Base URL of the Helios service. e.g. `https://helios.internal` */
  baseUrl: string;
  /** HMAC secret shared with Helios. */
  hmacSecret: string;
  /** Project token for the platform/root tenant. */
  projectToken: string;
  /** Service name to send as `x-source-service`. */
  sourceService?: string;
  /** Fetch timeout in ms. Default 2000. */
  fetchTimeoutMs?: number;
  /** Optional fetch impl injection for tests. */
  fetchImpl?: typeof fetch;
}

export type HeliosMembershipResolution =
  | { status: 'active'; role: string; permissions: Permission[] }
  | { status: 'inactive'; role: string }
  | { status: 'not_a_member' };

/** Thrown when the Helios request fails and the caller doesn't want stale-on-error. */
export class HeliosUnreachableError extends Error {
  constructor(
    message: string,
    public readonly cause: unknown,
  ) {
    super(message);
    this.name = 'HeliosUnreachableError';
  }
}

export class HeliosClient {
  private readonly baseUrl: string;
  private readonly hmacSecret: string;
  private readonly projectToken: string;
  private readonly sourceService: string;
  private readonly fetchTimeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: HeliosClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.hmacSecret = opts.hmacSecret;
    this.projectToken = opts.projectToken;
    this.sourceService = opts.sourceService ?? 'helios-permissions-sdk';
    this.fetchTimeoutMs = opts.fetchTimeoutMs ?? 2000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  /**
   * Fetch the resolved permission set for `(userId, tenantId)`. Returns
   * the discriminated union from Helios; the PermissionClient
   * translates `not_a_member` and `inactive` into empty arrays.
   *
   * Throws HeliosUnreachableError on network failure, timeout, or
   * non-2xx response (other than 404, which means not_a_member).
   */
  async fetchUserPermissions(
    userId: string,
    tenantId: string,
  ): Promise<HeliosMembershipResolution> {
    const path = `/internal/users/${encodeURIComponent(userId)}/permissions?tenantId=${encodeURIComponent(tenantId)}`;
    const url = `${this.baseUrl}${path}`;
    const timestamp = Math.floor(Date.now() / 1000).toString();

    const signature = this.sign('GET', path, timestamp);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.fetchTimeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: 'GET',
        headers: {
          'x-project-token': this.projectToken,
          'x-source-service': this.sourceService,
          'x-signature': signature,
          'x-timestamp': timestamp,
          'x-correlation-id': randomUUID(),
          accept: 'application/json',
        },
        signal: controller.signal,
      });
    } catch (err) {
      throw new HeliosUnreachableError(
        `HeliosClient.fetchUserPermissions: network error for (${userId}, ${tenantId})`,
        err,
      );
    } finally {
      clearTimeout(timeoutId);
    }

    if (response.status === 404) {
      // 404 means the row doesn't exist — treat as not_a_member.
      return { status: 'not_a_member' };
    }

    if (!response.ok) {
      throw new HeliosUnreachableError(
        `HeliosClient.fetchUserPermissions: HTTP ${response.status} for (${userId}, ${tenantId})`,
        null,
      );
    }

    const body = (await response.json()) as HeliosMembershipResolution;
    return body;
  }

  /**
   * Compute the HMAC-SHA256 signature per the contract.
   *
   * Payload: METHOD.upper() + fullPath + timestamp (fullPath includes
   * query string). Lowercase hex output.
   */
  private sign(method: string, fullPath: string, timestamp: string): string {
    const payload = `${method.toUpperCase()}${fullPath}${timestamp}`;
    return createHmac('sha256', this.hmacSecret).update(payload, 'utf8').digest('hex');
  }
}

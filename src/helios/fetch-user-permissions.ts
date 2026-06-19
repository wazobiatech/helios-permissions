// =============================================================================
// HeliosClient — HMAC-signed GET to Helios's permission endpoint.
//
// Helios exposes (v0.2.0):
//   GET /internal/permissions/:userId?tenantId=<uuid>
//   Headers: x-source-service, x-signature, x-timestamp
//   Window: 300 seconds (per Helios CLAUDE.md)
//
// The route is HMAC-only — no Authorization header, no project token,
// no user token. Knowing SIGNATURE_SHARED_SECRET is the entire auth
// model. This is the SDK's outbound contract.
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
// HMAC payload:
//   payload = method + path + timestamp
//   digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
//   reject if |now - timestamp| > 300s
//
// Where:
//   - `method` is the lowercase HTTP method (matches Helios's
//     hmac.ts verifier, which uses `req.method` from Express — lowercase).
//   - `path` is the URL path WITHOUT the query string (matches
//     `req.path` in Express, which strips the query string).
//
// Note: this deviates from the canonical nexus-mcp contract
// (METHOD.toUpperCase() + fullPath including query string). The
// deviation is forced by Helios's existing verifier at
// helios/src/internal/hmac.ts. If Helios is fixed to use the
// canonical contract, this can be reverted.
//
// We implement the signing here directly (instead of pulling in
// @wazobiatech/nexus-mcp) to keep the SDK's dependency surface minimal.
// =============================================================================

import { createHmac, randomUUID } from 'node:crypto';

import type { Permission } from '../role-permissions';
import type { Logger } from '../types/logger';
import { silentLogger } from '../types/logger';

export interface HeliosClientOptions {
  /** Base URL of the Helios service. e.g. `https://helios.internal` */
  baseUrl: string;
  /**
   * HMAC secret shared with Helios. Canonical env var name is
   * `SIGNATURE_SHARED_SECRET` (matches Hecate's convention).
   */
  signatureSharedSecret: string;
  /** Service name to send as `x-source-service`. */
  sourceService?: string;
  /** Fetch timeout in ms. Default 2000. */
  fetchTimeoutMs?: number;
  /** Optional fetch impl injection for tests. */
  fetchImpl?: typeof fetch;
  /** Optional logger for diagnostics. Defaults to silent. */
  logger?: Logger;
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
  private readonly signatureSharedSecret: string;
  private readonly sourceService: string;
  private readonly fetchTimeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly logger: Logger;

  constructor(opts: HeliosClientOptions) {
    if (opts.signatureSharedSecret === undefined || opts.signatureSharedSecret === '') {
      throw new Error('HeliosClient: signatureSharedSecret is required');
    }

    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.signatureSharedSecret = opts.signatureSharedSecret;
    this.sourceService = opts.sourceService ?? 'helios-permissions-sdk';
    this.fetchTimeoutMs = opts.fetchTimeoutMs ?? 2000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.logger = opts.logger ?? silentLogger;
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
    const path = `/internal/permissions/${encodeURIComponent(userId)}?tenantId=${encodeURIComponent(tenantId)}`;
    const url = `${this.baseUrl}${path}`;
    const timestamp = Math.floor(Date.now() / 1000).toString();

    // Sign the path WITHOUT the query string — Helios's
    // hmac.ts verifier signs `req.method + req.path` (Express's
    // req.path strips the query string). Mismatching the path would
    // produce a signature rejection on every call.
    const signPath = path.split('?')[0] ?? path;
    const signature = this.sign('GET', signPath, timestamp);

    const headers: Record<string, string> = {
      'x-source-service': this.sourceService,
      'x-signature': signature,
      'x-timestamp': timestamp,
      'x-correlation-id': randomUUID(),
      accept: 'application/json',
    };

    this.logger.debug(
      {
        url,
        method: 'GET',
        signedPath: signPath,
        timestamp,
        signature,
        sourceService: this.sourceService,
      },
      'HeliosClient.fetchUserPermissions: sending request',
    );

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.fetchTimeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });
    } catch (err) {
      this.logger.error(
        { err, userId, tenantId, url },
        'HeliosClient.fetchUserPermissions: network error',
      );
      throw new HeliosUnreachableError(
        `HeliosClient.fetchUserPermissions: network error for (${userId}, ${tenantId})`,
        err,
      );
    } finally {
      clearTimeout(timeoutId);
    }

    this.logger.debug(
      {
        userId,
        tenantId,
        status: response.status,
        statusText: response.statusText,
      },
      'HeliosClient.fetchUserPermissions: received response',
    );

    if (response.status === 404) {
      // 404 means the row doesn't exist — treat as not_a_member.
      this.logger.debug(
        { userId, tenantId },
        'HeliosClient.fetchUserPermissions: 404, treating as not_a_member',
      );
      return { status: 'not_a_member' };
    }

    if (!response.ok) {
      this.logger.error(
        { userId, tenantId, status: response.status },
        'HeliosClient.fetchUserPermissions: non-2xx response',
      );
      throw new HeliosUnreachableError(
        `HeliosClient.fetchUserPermissions: HTTP ${response.status} for (${userId}, ${tenantId})`,
        null,
      );
    }

    const body = (await response.json()) as HeliosMembershipResolution;
    this.logger.debug(
      { userId, tenantId, body },
      'HeliosClient.fetchUserPermissions: response body',
    );
    return body;
  }

  /**
   * Compute the HMAC-SHA256 signature.
   *
   * Payload: method + path + timestamp. The path is the URL path
   * WITHOUT the query string (matching Helios's hmac.ts verifier,
   * which signs `req.method + req.path`). The method is sent in
   * its original case (the verifier uses `req.method`, which Express
   * provides lowercase).
   *
   * Note: this deviates from the canonical nexus-mcp contract
   * (METHOD.toUpperCase() + fullPath including query string).
   * The deviation is forced by Helios's existing verifier — fixing
   * Helios to the canonical contract would let us switch back.
   */
  private sign(method: string, path: string, timestamp: string): string {
    const payload = `${method}${path}${timestamp}`;
    return createHmac('sha256', this.signatureSharedSecret)
      .update(payload, 'utf8')
      .digest('hex');
  }
}

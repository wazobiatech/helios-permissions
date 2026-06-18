// =============================================================================
// helios-client.spec.ts — exercise the HMAC signing + fetch path.
//
// The signing logic is the cross-SDK contract (matches nexus-mcp's
// HMAC-SHA256 payload = METHOD.upper() + path + timestamp). We test the
// signature shape and the request headers — the actual HTTP behavior
// is mocked via fetchImpl injection.
// =============================================================================

import { createHmac } from 'node:crypto';

import { HeliosClient, HeliosUnreachableError } from '../src/helios/fetch-user-permissions';

describe('HeliosClient — HMAC signing', () => {
  const SECRET = 'super-secret-key';

  it('signs METHOD.upper() + path + timestamp with HMAC-SHA256, lowercase hex', async () => {
    // Capture the actual headers the SDK produces. Verify the signature
    // matches a recomputation using the same path + timestamp — this is
    // what other SDKs (Python, Go) would also produce, byte-identical.
    const captured: { url?: string; headers?: Record<string, string> } = {};
    const mockFetch: typeof fetch = async (url, init) => {
      captured.url = String(url);
      captured.headers = init?.headers as Record<string, string>;
      return new Response(
        JSON.stringify({ status: 'active', role: 'OWNER', permissions: ['helios:tenant:transfer'] }),
        { status: 200 },
      );
    };

    const client = new HeliosClient({
      baseUrl: 'https://helios.internal',
      hmacSecret: SECRET,
      projectToken: 'pt-1',
      fetchImpl: mockFetch,
    });

    await client.fetchUserPermissions('u-1', 't-1');

    const timestamp = captured.headers!['x-timestamp'];
    const signature = captured.headers!['x-signature'];

    // Reconstruct the signed payload from the URL the SDK sent.
    // We re-derive the path the SDK signed by stripping the base URL.
    const urlStr = captured.url!;
    const signedPath = urlStr.replace('https://helios.internal', '');

    const expected = createHmac('sha256', SECRET)
      .update(`GET${signedPath}${timestamp}`, 'utf8')
      .digest('hex');

    expect(signature).toBe(expected);
    expect(signature).toMatch(/^[0-9a-f]{64}$/); // lowercase hex, 64 chars (SHA-256)
    expect(captured.headers!['x-source-service']).toBe('helios-permissions-sdk');
    expect(captured.headers!['x-project-token']).toBe('pt-1');
    expect(captured.headers!['x-correlation-id']).toBeDefined();
  });
});

describe('HeliosClient — response handling', () => {
  function makeClient(response: Response): { client: HeliosClient; captured: { url: string } } {
    const captured = { url: '' };
    const mockFetch: typeof fetch = async (url) => {
      captured.url = String(url);
      return response;
    };
    const client = new HeliosClient({
      baseUrl: 'https://helios.internal',
      hmacSecret: 'secret',
      projectToken: 'pt',
      fetchImpl: mockFetch,
    });
    return { client, captured };
  }

  it('translates 404 to not_a_member', async () => {
    const { client } = makeClient(new Response('', { status: 404 }));
    const result = await client.fetchUserPermissions('u-1', 't-1');
    expect(result).toEqual({ status: 'not_a_member' });
  });

  it('passes through active resolution', async () => {
    const { client } = makeClient(
      new Response(
        JSON.stringify({ status: 'active', role: 'OWNER', permissions: ['helios:tenant:transfer'] }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );
    const result = await client.fetchUserPermissions('u-1', 't-1');
    expect(result.status).toBe('active');
  });

  it('passes through inactive resolution', async () => {
    const { client } = makeClient(
      new Response(JSON.stringify({ status: 'inactive', role: 'VIEWER' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const result = await client.fetchUserPermissions('u-1', 't-1');
    expect(result.status).toBe('inactive');
  });

  it('throws HeliosUnreachableError on 500', async () => {
    const { client } = makeClient(new Response('', { status: 500 }));
    await expect(client.fetchUserPermissions('u-1', 't-1')).rejects.toBeInstanceOf(HeliosUnreachableError);
  });

  it('throws HeliosUnreachableError on network error', async () => {
    const mockFetch: typeof fetch = async () => {
      throw new Error('network error');
    };
    const client = new HeliosClient({
      baseUrl: 'https://helios.internal',
      hmacSecret: 'secret',
      projectToken: 'pt',
      fetchImpl: mockFetch,
    });
    await expect(client.fetchUserPermissions('u-1', 't-1')).rejects.toBeInstanceOf(HeliosUnreachableError);
  });

  it('encodes userId and tenantId in the path', async () => {
    const { client, captured } = makeClient(
      new Response(JSON.stringify({ status: 'not_a_member' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    await client.fetchUserPermissions('user/with/slashes', 'tenant with spaces');
    expect(captured.url).toContain('user%2Fwith%2Fslashes');
    expect(captured.url).toContain('tenant%20with%20spaces');
  });
});

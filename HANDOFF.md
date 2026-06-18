# @wazobiatech/helios-permissions — Handoff

> TypeScript SDK for the Nexus permission contract. Redis-cached
> `callerHasPermission`, NestJS module, event-driven invalidation.

## Status

| | |
|---|---|
| Version | **0.2.0** — HMAC-only auth model |
| Branch | `feature/ZIN-4901b--helios-permissions-sdk` |
| Tests | 71 passing across 6 suites |
| Build | `tsc` clean, dist/ generated |
| Typecheck | `tsc --noEmit` clean |

## What this SDK does

Single source of truth for cross-service authz: Helios's `user_projects`
table. Every service asks the SDK "can user U do perm P in tenant T?"
The SDK:

1. Checks Redis (one GET on the hot path).
2. On miss, fetches from Helios via HMAC-signed GET and populates the cache.
3. Translates Helios's discriminated union (active / inactive / not_a_member)
   into a flat `Permission[]` (empty for non-members and inactive).
4. On Helios error with no cache entry: denies by default (`staleOnError=true`).
5. Supports Helios's sync write-through path (after a role change in
   `user_projects`, Helios overwrites the cache directly with the new
   perm array — no race window).

## Authentication model (v0.2.0)

The Helios route is **HMAC-only**. Knowing `SIGNATURE_SHARED_SECRET` is
the entire auth surface — no `Authorization` header, no project token,
no user token, no `x-tenant-id` (the tenant is carried in the query
string, which the caller signs).

Why a static project token on an env var is wrong:
- A project token is **bound to one tenant** AND **expires**. Neither
  is compatible with a long-lived env var.
- The Helios `/internal/permissions/:userId?tenantId=...` route (ZIN-4901e
  in helios) is gated by `SIGNATURE_SHARED_SECRET` alone. The service
  calling the SDK proves it knows the secret by signing the request.

The previous v0.1.0 design used `x-project-token` against the legacy
`/internal/users/:userId/permissions` route (which is the Mercury target
and requires the full set of headers). That contract is now exclusive
to Mercury. The SDK uses the new HMAC-only route.

The `HeliosClient` constructor takes `signatureSharedSecret` (the
canonical name, matches Hecate's `SIGNATURE_SHARED_SECRET` env var).

## Files

```
src/
  index.ts                            # Public API barrel
  role-permissions.ts                 # Permission union + ROLE_PERMISSIONS map
  permission-client.ts                # PermissionClient (hot-path authz)
  factory.ts                          # createPermissionClient() factory
  logger.ts                           # Logger protocol + silent/console defaults
  types/
    logger.ts                         # Logger interface
  cache/
    index.ts
    cache.ts                          # PermissionCache interface
    in-memory-permission-cache.ts     # Map impl (tests)
    redis-permission-cache.ts         # Redis impl (production)
  helios/
    index.ts
    fetch-user-permissions.ts         # HeliosClient (HMAC-signed GET)
  nestjs/                             # NestJS module + PERMISSION_CLIENT injection token
tests/
  role-permissions.spec.ts            # ROLE_PERMISSIONS matrix
  in-memory-permission-cache.spec.ts  # Cache contract
  redis-permission-cache.spec.ts      # Redis impl via ioredis-mock
  helios-client.spec.ts               # HMAC signing + response handling
  permission-client.spec.ts           # Hot path, fail-closed, coalescing
  helios-event.invalidator.spec.ts    # Event-driven cache invalidation
```

## Decisions locked

- **HMAC-only auth model (v0.2.0).** No project tokens, no service
  tokens, no Mercury-credentials exchange. The route is gated by
  `SIGNATURE_SHARED_SECRET` alone.
- **Drop JWT `permissions[]` claim.** Every service uses the SDK for
  authz; the JWT is identity-only. (Follow-up: file in Mercury HANDOFF.)
- **Drop `@UserAuth(['perm:...'])` scope checks.** Service-layer
  `callerHasPermission` is the only gate. (Follow-up: per-service PRs.)
- **`PERMISSION_REDIS_URL` shared by all services + Helios.** Single
  Redis instance per cluster (v1); Sentinel/Cluster when scaling beyond
  one box.
- **Write-through from Helios.** Sync cache overwrite after role change
  — sub-millisecond staleness window. Event-driven invalidation as backup.
- **Fail-closed default.** Helios down + no cache → deny. Opt out via
  `staleOnError: false`.
- **No wildcards in JWT.** Every perm enumerated.
- **No encryption.** JWT perms are plain JSON; SDK perms are plain JSON.

## Cache semantics

| Op | Behavior |
|---|---|
| `get(userId, tenantId)` | Redis GET. On miss → `undefined`. On error → log warn + `undefined` (fall-through). |
| `set(...)` | `SET ... NX EX 60`. Stale-populate race protection. On error → log warn + swallow. |
| `writeThrough(...)` | `SET ... EX 60` (no NX). Used by Helios after a role change. |
| `invalidate(userId, tenantId?)` | `DEL` (specific) or `SCAN MATCH ... \| DEL` (all). On error → log error + throw. |
| `invalidateTenant(tenantId)` | `SCAN MATCH helios:perms:*:{tenantId} \| DEL`. On error → throw. |

## Concurrent read coalescing

In-process lock keyed by `(userId, tenantId)`. The first concurrent
reader fetches from Helios; subsequent readers await the same promise.
Verified in `permission-client.spec.ts` — 20 concurrent reads on cold
cache result in 1 Helios call.

## Environment variables

| Var | Required | Description |
|---|---|---|
| `HELIOS_BASE_URL` | yes | e.g. `https://helios.internal` |
| `SIGNATURE_SHARED_SECRET` | yes | HMAC-SHA256 shared secret (canonical name) |
| `PERMISSION_REDIS_URL` | yes | Shared Redis URL across all services |

> **Removed in v0.2.0:** `HELIOS_PROJECT_TOKEN` is no longer needed.
> The new HMAC-only route is gated by `SIGNATURE_SHARED_SECRET` alone.
> Project tokens are tenant-bound AND expire, so they were never a
> good fit for an env var.
>
> **Deprecated alias:** `HELIOS_HMAC_SECRET` → use `SIGNATURE_SHARED_SECRET`.
> The v0.1.0 `hmacSecret` field on `HeliosClient` is still accepted for
> back-compat; the v0.1.0 `heliosHmacSecret` factory field is still
> accepted as a back-compat alias.

## Cross-SDK consistency

HMAC signing logic matches `wazobiatech/nexus-mcp-contract`:

```
payload = METHOD.upper() + fullPath + timestamp
digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
reject if |now - timestamp| > 300s
```

The Python SDK (`wazobiatech-helios-permissions`) and this TypeScript
SDK produce byte-identical signatures for the same inputs. Verified
independently in each SDK's test suite.

The HMAC-only route (`GET /internal/permissions/:userId?tenantId=...`)
is implemented in helios as ZIN-4901e (`ServicePermissionsController`
+ `hmacServicePermissionsMiddleware`).

## Out of scope (deferred)

- **Permission contract repo** (`wazobiatech/permission-contract` —
  language-agnostic JSON files mirrored from this map). The contract
  ticket is ZIN-4901a. The SDK is structured so the JSON can replace the
  hardcoded tuples in `role-permissions.ts` via codegen in v0.2.0.
- **Python / Go / Laravel SDKs.** Mirror packages. Same API surface.
- **Multi-instance Redis lock.** Use Redis-based SET NX EX for global
  coalescing when scaling beyond ~5 instances.
- **Redis Sentinel / Cluster support.** v1 is single instance.
- **Helios event-listener transport.** The SDK can subscribe to
  `helios.events` to keep the cache fresh. The Hecate-driven invalidation
  path is the v0.2.0 priority; Kafka subscription is a follow-up.

## Verification

```bash
yarn install
yarn lint                 # eslint clean (warnings only in pre-existing logger.ts)
yarn typecheck            # tsc --noEmit clean
yarn test                 # 71/71 pass
yarn test:ci              # jest --ci --coverage --verbose
```

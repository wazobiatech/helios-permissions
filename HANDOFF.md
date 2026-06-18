# @wazobiatech/helios-permissions — Handoff

> TypeScript SDK for the Nexus permission contract. Redis-cached
> `callerHasPermission`, NestJS module, event-driven invalidation.

## Status

| | |
|---|---|
| Version | 0.1.0 (initial release) |
| Branch | `feature/ZIN-4901b--helios-permissions-sdk` |
| Tests | 67 passing across 6 suites |
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
4. On Helios error with no cache entry: denies by default (`staleOnError: true`).
5. Supports Helios's sync write-through path (after a role change in
   `user_projects`, Helios overwrites the cache directly with the new
   perm array — no race window).
6. Supports event-driven invalidation as a backup (Kafka consumers call
   `invalidate(userId[, tenantId])` on the four Helios events that
   affect perms).

## Files

```
src/
  index.ts                              # Public API barrel
  role-permissions.ts                   # Permission union + ROLE_PERMISSIONS map
  permission-client.ts                  # PermissionClient (hot-path authz)
  factory.ts                            # createPermissionClient(opts)
  cache/
    permission-cache.interface.ts       # PermissionCache abstraction
    redis-permission-cache.ts           # Redis impl (production)
    in-memory-permission-cache.ts       # Map impl (tests)
    index.ts
  helios/
    fetch-user-permissions.ts           # HeliosClient (HMAC-signed GET)
    index.ts
  types/
    logger.ts                           # Logger interface + silent/console defaults
  nestjs/
    permissions.module.ts               # forRoot() + forRootAsync() + PERMISSION_CLIENT
    require-permission.decorator.ts     # @RequirePermission + guard
    consumers/
      helios-event.invalidator.ts       # 4 event handlers
    index.ts
tests/
  role-permissions.spec.ts              # ROLE_PERMISSIONS matrix
  in-memory-permission-cache.spec.ts    # Cache contract (NX, writeThrough, TTL)
  redis-permission-cache.spec.ts        # Redis impl via ioredis-mock
  permission-client.spec.ts             # Hot-path authz, coalescing, fail-closed
  helios-event.invalidator.spec.ts      # Event handlers
  helios-client.spec.ts                 # HMAC signing + response handling
```

## Decisions locked

- **Drop JWT `permissions[]` claim.** Every service uses the SDK for authz;
  the JWT is identity-only. (Follow-up: file in Mercury HANDOFF.)
- **Drop `@UserAuth(['perm:...'])` scope checks.** Service-layer
  `callerHasPermission` is the only gate. (Follow-up: per-service PRs.)
- **`PERMISSION_REDIS_URL` shared by all services + Helios.** Single Redis
  instance per cluster (v1); Sentinel/Cluster when scaling beyond one box.
- **Write-through from Helios.** Sync cache overwrite after role change —
  sub-millisecond staleness window. Event-driven invalidation as backup.
- **Fail-closed default.** Helios down + no cache → deny. Opt out via
  `staleOnError: false`.
- **No wildcards in JWT.** Every perm enumerated (when we had perms in
  JWT, which we don't anymore post-migration).
- **No encryption.** JWT perms were plain JSON; SDK perms are plain JSON.

## Cache semantics

| Op | Behavior |
|---|---|
| `get(userId, tenantId)` | Redis GET. On miss → `null`. On error → log warn + `null` (fall-through). |
| `set(...)` | `SET ... NX EX 60`. Stale-populate race protection. On error → log warn + swallow. |
| `writeThrough(...)` | `SET ... EX 60` (no NX). Used by Helios after a role change. |
| `invalidate(userId, tenantId?)` | `DEL` (specific) or `SCAN MATCH ... \| DEL` (all). On error → log error + throw. |
| `invalidateTenant(tenantId)` | `SCAN MATCH helios:perms:*:{tenantId} \| DEL`. On error → throw. |

## Concurrent read coalescing

In-process lock keyed by `(userId, tenantId)`. The first concurrent reader
fetches from Helios; subsequent readers await the same promise. Verified
in `permission-client.spec.ts` — 20 concurrent reads on cold cache
result in 1 Helios call.

For multi-instance deployments, Helios is hit ~N times (once per
instance). Global coalescing via Redis lock is a v2 optimization.

## Environment variables

| Var | Required | Description |
|---|---|---|
| `HELIOS_BASE_URL` | yes | e.g. `https://helios.internal` |
| `HELIOS_HMAC_SECRET` | yes | Shared HMAC-SHA256 secret |
| `HELIOS_PROJECT_TOKEN` | yes | Project token for the platform tenant |
| `PERMISSION_REDIS_URL` | yes | Shared Redis URL across all services |

## Out of scope (deferred)

- **Permission contract repo** (`wazobiatech/permission-contract` —
  language-agnostic JSON files mirrored from this map). The contract
  ticket is ZIN-4901a. The SDK is structured so the JSON can replace the
  hardcoded tuples in `role-permissions.ts` via codegen in v0.2.0.
- **Python / Go / Laravel SDKs.** Mirror packages. Same API surface.
- **Multi-instance Redis lock.** Use Redis-based SET NX EX for global
  coalescing when scaling beyond ~5 instances.
- **Redis Sentinel / Cluster support.** v1 is single instance.
- **NestJS test harness.** `permissions.module.ts` and
  `require-permission.decorator.ts` are exercised in adopting services'
  integration tests. v0.1.0 coverage thresholds reflect this (60% global).

## Cross-SDK consistency

HMAC signing logic matches `wazobiatech/nexus-mcp-contract`:

```
payload = METHOD.upper() + fullPath + timestamp
digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
reject if |now - timestamp| > 300s
```

When the Python / Go SDKs land, they must produce byte-identical
signatures for the same inputs. Verified in
`helios-client.spec.ts` — the signature recomputation matches the SDK's
output exactly.

## Verification

```bash
npm install
npm run typecheck   # clean
npm run build       # dist/ generated
npm test            # 67/67 pass
npm run test:ci     # + coverage report
```

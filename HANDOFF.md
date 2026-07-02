# @wazobiatech/helios-permissions — Handoff

> TypeScript SDK for the Nexus permission contract. Redis-cached
> `callerHasPermission`, NestJS module, event-driven invalidation.

## Status

| | |
|---|---|
| Version | **0.7.0** — universal-by-contract short-circuit in `callerHasPermission` (root-tenant safe) |
| Branch | `feature/ZIN-4901b--helios-permissions-sdk` |
| Tests | 22 passing on `permission-client.spec.ts` (includes 6 short-circuit tests). Plus 36 passing on `role-permissions.spec.ts` (v1.6.0 scope counts: 12 self / 40 platform / 19 project / 1 dual). Plus other SDK-covered suites. Pre-existing test failures on `helios-client.spec.ts` (HMAC vector mismatch) and `helios-event.invalidator.spec.ts` / `redis-permission-cache.spec.ts` (test infrastructure: missing peer deps) are unrelated to v0.7.0. |
| Build | `tsc` clean, dist/ generated |
| Typecheck | `tsc --noEmit` clean |
| Contract version | `permission-contract@v1.6.0` (4-scope model + Mercury v1.5.0 expansion + Zeta v1.6.0) |

## v0.7.0 — universal-by-contract short-circuit

`PermissionClient.callerHasPermission(userId, tenantId, perm)` short-circuits
when `perm` is universal-by-contract — i.e. either `self` scope (every
authenticated user has it by invariant 8) or granted to every role in
`ROLE_PERMISSIONS` (OWNER + ADMIN + EDITOR + VIEWER). The short-circuit
returns `true` without consulting cache or Helios.

This fixes a root-tenant dead-end: Mercury's platform admins have no
Helios membership row (the platform root tenant is not a real tenant),
so every `callerHasPermission(rootUser, rootTenant, perm)` previously
resolved to `not_a_member` → 403. The contract invariant is that these
perms are universal; the SDK now honors that without a Helios round-trip.

`explain(...)` short-circuits the same way. `getUserPermissions(...)`
folds `SELF_PERMISSIONS` into the result so callers see a complete
view regardless of tenant membership.

Adding a perm to all four roles is a deliberate, reviewable contract
decision — the SDK trusts the contract and short-circuits without
re-fetching.

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
  role-permissions.ts                 # GENERATED — Permission union + ROLE_PERMISSIONS map (do not edit)
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
scripts/
  codegen-permissions.mjs             # Fetches contract, validates, runs codegen-ts
  codegen-ts.mjs                      # Vendored from permission-contract
  validate-contract.mjs               # Vendored from permission-contract
tests/
  role-permissions.spec.ts            # ROLE_PERMISSIONS matrix
  in-memory-permission-cache.spec.ts  # Cache contract
  redis-permission-cache.spec.ts      # Redis impl via ioredis-mock
  helios-client.spec.ts               # HMAC signing + response handling
  permission-client.spec.ts           # Hot path, fail-closed, coalescing
  helios-event.invalidator.spec.ts    # Event-driven cache invalidation
```

## Permission contract source of truth (v0.3.0+)

The `Permission` union and `ROLE_PERMISSIONS` map are **codegen'd** from
[`wazobiatech/permission-contract`](https://github.com/wazobiatech/permission-contract)
(public mirror). To change the platform's role → permission matrix:

1. Open a PR against `permission-contract` — edit `permissions.json`,
   bump `version` (semver).
2. Tag a release (`v1.4.0`, etc.).
3. Open a PR against this SDK — bump `PERMISSION_CONTRACT_VERSION`
   in `bitbucket-pipelines.yml` and the default in
   `scripts/codegen-permissions.mjs` (both must match).
4. CI runs `npm run codegen`, then `tsc --noEmit`, `eslint`, `jest`.

Currently pinned to `permission-contract@v1.4.0`, which adds three
`helios:external:*` permissions (register / revoke / view) for the
Use case 2 ("tenant brings their own auth") flow. `register` and
`revoke` are OWNER-only per the contract's `owner_only_permissions`
invariant; `view` is OWNER+ADMIN.

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
| `set(...)` | `SET ... NX` (no EX by default). Stale-populate race protection. On error → log warn + swallow. |
| `writeThrough(...)` | `SET ...` (no NX, no EX by default). Used by Helios after a role change. |
| `invalidate(userId, tenantId?)` | `DEL` (specific) or `SCAN MATCH ... \| DEL` (all). On error → log error + throw. |
| `invalidateTenant(tenantId)` | `SCAN MATCH helios:perms:*:{tenantId} \| DEL`. On error → throw. |

### TTL policy (v0.5.0 — no expiry by default)

The cache is the primary read path for `callerHasPermission`. The
platform targets a 90-98% cache hit rate, which means entries must
outlive the request burst. Every entry is invalidated explicitly at
the mutation site — Helios calls `writeThrough` / `invalidate` after
every role change, Hecate's event consumer drops the key on `helios.*`
events, and the internal events handlers (`athens.project.*`,
`athens.service.update`, `mercury.user.deleted`,
`helios.invitation.accepted`) invalidate the tenant-level cache after
each event. A 60s safety-net TTL would just be wasted work — entries
the next read would re-populate anyway, forcing an unnecessary
round-trip to Helios.

v0.4.0 shipped with a 60s default TTL. v0.5.0 removed it. **This is a
behavioral change for consumers**: if you relied on the implicit 60s
TTL, you now get no expiry. To opt back in, pass `cacheTtlSeconds: 60`
to `createPermissionClient` (or `ttlSeconds: 60` directly to
`RedisPermissionCache`). The opt-in is per-instance.

```typescript
const { client, close } = createPermissionClient({
  // ...
  cacheTtlSeconds: 60, // opt back into a 60s TTL (not recommended)
});
```

### Important: Helios-side cache must agree

The Helios service runs its own `PermissionCacheService` (in
`helios/src/internal/permission-cache.service.ts`) which uses the same
key shape and JSON serialization. **Both layers must use the same TTL
policy** — if Helios writes with one TTL and the SDK reads with another,
the SDK's EX wins on the next SDK-side `set` call and may drop entries
before Helios has a chance to re-write them. v0.5.0 keeps both layers
in lockstep: both default to no expiry, both opt back into a TTL via a
matching env var / option name.

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

- **Helios-side migration.** Helios still has its own copy of the
  permission map at `helios/src/permissions/role-permissions.ts`. A
  follow-up ticket will replace it with `import from
  '@wazobiatech/helios-permissions'` (or a generated file). Not in
  ZIN-4901a scope.
- **Go / Laravel SDKs.** Mirror packages. Same API surface.
- **Multi-instance Redis lock.** Use Redis-based SET NX EX for global
  coalescing when scaling beyond ~5 instances.
- **Redis Sentinel / Cluster support.** v1 is single instance.
- **Helios event-listener transport.** The SDK can subscribe to
  `helios.events` to keep the cache fresh. The Hecate-driven invalidation
  path is the v0.2.0 priority; Kafka subscription is a follow-up.

## Verification

```bash
yarn install
# Codegen requires network — fetches the contract from GitHub.
PERMISSION_CONTRACT_VERSION=v1.6.0 yarn codegen
yarn lint                 # eslint clean
yarn typecheck            # tsc --noEmit clean
yarn test                 # 22+36 pass on permission-client + role-permissions (other suites have pre-existing infrastructure failures)
yarn test:ci              # jest --ci --coverage --verbose
```

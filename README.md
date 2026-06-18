# @wazobiatech/helios-permissions

> TypeScript SDK for the Nexus permission contract — Redis-cached
> `callerHasPermission`, NestJS module, and event-driven cache invalidation.

## What it does

Every service in the platform needs to answer the same question: **"is this
user allowed to do X in tenant Y?"** The answer lives in Helios's
`user_projects` table (one row per user-per-tenant with a role). This SDK
is the client for that source of truth, with three properties that matter
in production:

1. **Cache-first** — Redis-cached (60s TTL), so the hot path is one Redis
   GET. Misses fetch from Helios and populate.
2. **Event-driven invalidation** — Helios writes to the cache synchronously
   after every role change (write-through). Kafka events invalidate
   downstream caches as a backup.
3. **Fail-closed** — if Helios is unreachable and no cache entry exists,
   the SDK denies by default. Operators page; users see 403 until Helios
   recovers. Better than serving potentially-stale perms during an outage.

## Install

```bash
npm install @wazobiatech/helios-permissions
```

The only runtime dependency is `ioredis`. The NestJS bits are optional
peer dependencies.

## Usage

### Hot-path authz decision

```typescript
import { createPermissionClient } from '@wazobiatech/helios-permissions';

const { client, close } = createPermissionClient({
  heliosBaseUrl: process.env.HELIOS_BASE_URL!,
  heliosHmacSecret: process.env.HELIOS_HMAC_SECRET!,
  heliosProjectToken: process.env.HELIOS_PROJECT_TOKEN!,
  redisUrl: process.env.PERMISSION_REDIS_URL!,
});

// In a resolver / handler:
const allowed = await client.callerHasPermission(userId, tenantId, 'helios:members:update');
if (!allowed) throw new ForbiddenException();

// On shutdown:
await close();
```

### NestJS module

```typescript
import { PermissionsModule, PERMISSION_CLIENT } from '@wazobiatech/helios-permissions/nestjs';
import type { PermissionClient } from '@wazobiatech/helios-permissions';

@Module({
  imports: [
    PermissionsModule.forRoot({
      heliosBaseUrl: process.env.HELIOS_BASE_URL!,
      heliosHmacSecret: process.env.HELIOS_HMAC_SECRET!,
      heliosProjectToken: process.env.HELIOS_PROJECT_TOKEN!,
      redisUrl: process.env.PERMISSION_REDIS_URL!,
    }),
  ],
})
export class AppModule {}

// In a service:
constructor(@Inject(PERMISSION_CLIENT) private readonly perms: PermissionClient) {}

async changeRole(actor: string, tenantId: string, userId: string, newRole: RoleType) {
  const granted = await this.perms.callerHasPermission(actor, tenantId, 'helios:roles:update');
  if (!granted) throw new ForbiddenException();
  // ... do the change ...
  // Sync write-through: next read sees the new perms immediately.
  await this.perms.writeThrough(userId, tenantId, ROLE_PERMISSIONS[newRole]);
}
```

### Pure role → perm map (used by Helios itself)

```typescript
import { ROLE_PERMISSIONS, resolvePermissions, roleHasPermission } from '@wazobiatech/helios-permissions/role-permissions';

resolvePermissions('OWNER'); // every perm in every service
roleHasPermission('VIEWER', 'helios:tenant:transfer'); // false
```

## Permission vocabulary

Permissions follow `{service}:{resource}:{action}`. The closed union:

- `athens:project:view` / `update` / `delete`
- `athens:services:enable` / `disable`
- `athens:team:invite` / `remove`
- `mercury:users:read` / `write`
- `mercury:api_keys:manage`
- `mercury:connections:read`
- `muse:posts:read` / `write` / `delete`
- `muse:drafts:read` / `write`
- `helios:members:view` / `invite` / `remove`
- `helios:roles:assign` / `revoke`
- `helios:invitations:create` / `revoke`
- `helios:tenant:switch` / `transfer`

## Role → Permission map

| Role | What they get |
|---|---|
| `OWNER` | Everything in every service, including `helios:tenant:transfer` |
| `ADMIN` | Everything except destructive `*:delete` and `helios:tenant:transfer` |
| `EDITOR` | Read + write on content services; no team mgmt |
| `VIEWER` | Read-only across all services |

`helios:tenant:switch` is granted to every role (it's a navigation gesture).

## Environment variables

| Var | Required | Description |
|---|---|---|
| `HELIOS_BASE_URL` | yes | e.g. `https://helios.internal` |
| `HELIOS_HMAC_SECRET` | yes | HMAC-SHA256 secret shared with Helios |
| `HELIOS_PROJECT_TOKEN` | yes | Project token for the platform tenant |
| `PERMISSION_REDIS_URL` | yes | Shared Redis URL — Helios and all services use the same instance |

## Cache semantics

- **Key shape:** `helios:perms:{userId}:{tenantId}` → JSON `Permission[]`
- **TTL:** 60 seconds (the safety net for missed invalidations)
- **Populate:** `SET ... NX EX 60` — never overwrites a concurrent populate (avoids stale-resurrection after invalidate race)
- **Write-through (Helios only):** `SET ... EX 60` (no NX) — Helios KNOWS the new value, overwrites unconditionally
- **Invalidate:** `SCAN MATCH ... | DEL` (non-blocking) for `invalidate(userId)` / `invalidateTenant`. Direct `DEL` for `invalidate(userId, tenantId)`.
- **Negative cache:** `[]` (empty array) means "user is not a member" — distinct from `null` (miss).
- **Failure modes:**
  - Redis GET fails → log + return null (caller falls through to Helios)
  - Redis SET fails → log + swallow (best-effort; cache miss next time)
  - Redis DEL fails → log + throw (operators need to know — TTL is the only safety net)

## Concurrent read coalescing

The SDK coalesces concurrent cold-cache reads via an in-process lock keyed
by `(userId, tenantId)`. The first concurrent reader fetches from Helios;
subsequent readers await the same promise. No thundering herd.

For multi-instance deployments, each instance runs its own lock — Helios
is still hit ~N times (one per instance). For global coalescing, add a
Redis-lock layer (deferred for v1).

## Event-driven invalidation

Helios writes to the cache synchronously after every perm change. As a
backup, every service can wire the four-event consumer:

```typescript
import { HeliosEventInvalidator } from '@wazobiatech/helios-permissions/nestjs';

const invalidator = new HeliosEventInvalidator(perms);

kafkaConsumer.on('helios.member.removed', (e) => invalidator.onMemberRemoved(e));
kafkaConsumer.on('helios.role.changed', (e) => invalidator.onRoleChanged(e));
kafkaConsumer.on('helios.invitation.accepted', (e) => invalidator.onInvitationAccepted(e));
kafkaConsumer.on('helios.ownership.transferred', (e) => invalidator.onOwnershipTransferred(e));
```

## HMAC contract

Matches `wazobiatech/nexus-mcp-contract`. Payload:

```
payload = METHOD.upper() + fullPath + timestamp
digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
reject if |now - timestamp| > 300s
```

Full path includes the query string. The signature is sent as
`x-signature` with `x-timestamp` (Unix seconds).

## Tests

```bash
npm test          # one run
npm run test:ci   # CI mode (coverage)
```

67 tests across 6 suites cover:
- Role × Permission map (every role, every perm)
- `InMemoryPermissionCache` (NX semantics, writeThrough, invalidate, TTL)
- `RedisPermissionCache` (via `ioredis-mock` — SET NX EX, SCAN, JSON serialization, error handling)
- `HeliosClient` (HMAC signing, response handling, error paths)
- `PermissionClient` (cache-first, fail-closed, concurrent coalescing, writeThrough, explain)
- `HeliosEventInvalidator` (all four event handlers, missing-payload grace)

## License

MIT — Wazobia Tech

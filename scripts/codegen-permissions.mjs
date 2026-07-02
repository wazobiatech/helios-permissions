#!/usr/bin/env node
// =============================================================================
// @wazobiatech/helios-permissions — codegen for role-permissions.ts.
//
// Fetches the canonical permission contract from
//   github.com/wazobiatech/permission-contract (public mirror)
// and emits src/role-permissions.ts. The emitted file is the
// source of truth in the SDK — there is NO runtime JSON parsing.
//
// Why codegen, not runtime loading:
//   The SDK exposes a closed `Permission` union for compile-time typo
//   detection (a caller passing "helios:members:Updte" should fail at
//   tsc, not at runtime via `isPermission`). Codegen keeps that.
//
// Contract version is pinned by PERMISSION_CONTRACT_VERSION (env var)
// so SDK releases don't silently drift when the contract bumps.
//
// Usage:
//   PERMISSION_CONTRACT_VERSION=v1.5.0 node scripts/codegen-permissions.mjs
//   # default version: v1.5.0
//
// Network failure is fatal — there is no fallback to a checked-in
// permissions.json. The contract is the single source of truth; an
// offline build that uses a stale contract would defeat the purpose.
// =============================================================================

import { writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const GENERATED_FILE = resolve(ROOT, 'src/role-permissions.ts');
const CODEGEN_SCRIPT = resolve(__dirname, 'codegen-ts.mjs');

const CONTRACT_VERSION = process.env.PERMISSION_CONTRACT_VERSION ?? 'v1.6.0';
const CONTRACT_URL = `https://raw.githubusercontent.com/wazobiatech/permission-contract/${CONTRACT_VERSION}/permissions.json`;

function log(msg) {
  process.stdout.write(`[codegen] ${msg}\n`);
}

function fail(msg) {
  process.stderr.write(`[codegen] FATAL: ${msg}\n`);
  process.exit(1);
}

async function fetchContractJson() {
  log(`fetching ${CONTRACT_URL}`);
  const res = await fetch(CONTRACT_URL);
  if (!res.ok) {
    fail(`contract fetch returned ${res.status} ${res.statusText}`);
  }
  return await res.json();
}

function runCodegenTs(contractPath) {
  // The codegen script is invoked as a child process so its stdout
  // (the generated source) is captured cleanly.
  return execFileSync('node', [CODEGEN_SCRIPT, contractPath], { encoding: 'utf8' });
}

function validateContractInMemory(contract) {
  // Lightweight re-validation so a malformed contract can't silently
  // produce broken code. Mirrors the script's invariants — keep in
  // sync if validate-contract.mjs gains new checks.
  if (!contract.version) fail('contract missing version');
  if (!contract.services || !Array.isArray(contract.services)) fail('contract missing services[]');
  if (!contract.roles || !Array.isArray(contract.roles)) fail('contract missing roles[]');
  if (!contract.permissions || typeof contract.permissions !== 'object') {
    fail('contract missing permissions{}');
  }
  if (!contract.role_permissions || typeof contract.role_permissions !== 'object') {
    fail('contract missing role_permissions{}');
  }

  const VALID_SCOPES = new Set(['self', 'platform', 'project', 'platform/project']);
  const flat = new Map(); // name → { service, scope }
  for (const [service, perms] of Object.entries(contract.permissions)) {
    if (!Array.isArray(perms)) fail(`permissions[${service}] is not an array`);
    for (const p of perms) {
      if (typeof p === 'string') {
        fail(`permissions[${service}] contains a bare string perm "${p}" — v1.3.0 requires {name, scope} objects`);
      }
      if (!p || typeof p !== 'object') {
        fail(`permissions[${service}] contains a non-object perm: ${JSON.stringify(p)}`);
      }
      if (typeof p.name !== 'string' || !p.name) {
        fail(`permissions[${service}] has a perm with missing/invalid name: ${JSON.stringify(p)}`);
      }
      if (!VALID_SCOPES.has(p.scope)) {
        fail(`perm "${p.name}" has invalid scope "${p.scope}" (must be one of: ${[...VALID_SCOPES].join(', ')})`);
      }
      if (p.scope === 'self' && !p.name.endsWith(':self')) {
        fail(`perm "${p.name}" has scope "self" but is missing the ":self" suffix`);
      }
      if (p.name.endsWith(':self') && p.scope !== 'self') {
        fail(`perm "${p.name}" ends with ":self" but scope is "${p.scope}" (must be "self")`);
      }
      flat.set(p.name, { service, scope: p.scope });
    }
  }

  for (const [role, def] of Object.entries(contract.role_permissions)) {
    const rolePerms = def.permissions || [];
    for (const perm of rolePerms) {
      const info = flat.get(perm);
      if (!info) {
        fail(`role "${role}" references unknown perm "${perm}"`);
      }
      if (info.scope === 'self') {
        fail(`role "${role}" contains self-scope perm "${perm}" — self perms are universal and must not be in any role`);
      }
      if (info.scope === 'project') {
        fail(`role "${role}" contains project-scope perm "${perm}" — project perms are tenant-user only and must not be in any role`);
      }
    }
    if (role !== 'OWNER' && rolePerms.includes('helios:tenant:transfer')) {
      fail(`role "${role}" has OWNER-only perm helios:tenant:transfer`);
    }
  }

  // helios:tenant:switch:self must be present and have scope "self"
  const SWITCH = 'helios:tenant:switch:self';
  const switchInfo = flat.get(SWITCH);
  if (!switchInfo) {
    fail(`required perm "${SWITCH}" is missing from permissions[service]`);
  } else if (switchInfo.scope !== 'self') {
    fail(`perm "${SWITCH}" must have scope "self" (universal perm), got "${switchInfo.scope}"`);
  }
}

async function main() {
  const contract = await fetchContractJson();
  validateContractInMemory(contract);

  // Persist a copy locally so the codegen script (which takes a file
  // path) can read it. Lives in .contracts/ — gitignored.
  const contractsDir = resolve(ROOT, '.contracts');
  mkdirSync(contractsDir, { recursive: true });
  const contractPath = resolve(contractsDir, `permissions-${contract.version}.json`);
  writeFileSync(contractPath, JSON.stringify(contract, null, 2));
  log(`cached contract at ${contractPath}`);

  const generated = runCodegenTs(contractPath);
  mkdirSync(dirname(GENERATED_FILE), { recursive: true });
  writeFileSync(GENERATED_FILE, generated);

  if (!generated.includes(`permission-contract v${contract.version}`)) {
    fail(`generated source does not reference contract version ${contract.version}`);
  }
  log(`wrote ${GENERATED_FILE}`);
  log(`done — src/role-permissions.ts derived from permission-contract ${contract.version}`);
}

main().catch(err => fail(err.stack ?? err.message));
#!/usr/bin/env node
// =============================================================================
// permission-contract — Validator.
//
// Refuses to exit 0 unless ALL invariants pass. Used in CI before any
// release tag is pushed. Also safe to run locally: `node scripts/validate.mjs`.
//
// Invariants (see README.md for prose):
//   1. permissions.json parses.
//   2. permissions.json matches permissions.schema.json (JSON Schema draft-07).
//   3. Permission union is closed: every perm in role_permissions is listed
//      under permissions[service].
//   4. No duplicate perms within any single role.
//   5. helios:tenant:switch is present in every role.
//   6. helios:tenant:transfer is present only in OWNER.
//   7. Every role has >=1 permission.
//   8. services[] and roles[] are unique.
// =============================================================================

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const CONTRACT_PATH = resolve(ROOT, 'permissions.json');
const SCHEMA_PATH = resolve(ROOT, 'permissions.schema.json');

/**
 * Minimal JSON Schema validator. We don't want a runtime dep on ajv
 * (the contract repo ships zero npm deps). The schema is constrained
 * enough that a hand-rolled validator covers every case that matters.
 *
 * Returns { ok: true } or { ok: false, errors: string[] }.
 */
function validateSchema(value, schema, path = '$') {
  const errors = [];

  function fail(msg) {
    errors.push(`${path}: ${msg}`);
  }

  if (schema.type) {
    const actual = Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
    if (schema.type !== actual) {
      fail(`expected type ${schema.type}, got ${actual}`);
      return { ok: false, errors };
    }
  }

  if (schema.type === 'object') {
    if (schema.required) {
      for (const key of schema.required) {
        if (!(key in value)) fail(`missing required property "${key}"`);
      }
    }
    if (schema.additionalProperties === false && schema.properties) {
      for (const key of Object.keys(value)) {
        if (!(key in schema.properties)) fail(`unexpected property "${key}"`);
      }
    }
    for (const [key, subSchema] of Object.entries(schema.properties ?? {})) {
      if (key in value) {
        const sub = validateSchema(value[key], subSchema, `${path}.${key}`);
        if (!sub.ok) errors.push(...sub.errors);
      }
    }
  }

  if (schema.type === 'array') {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      fail(`array length ${value.length} < minItems ${schema.minItems}`);
    }
    if (schema.uniqueItems) {
      const seen = new Set();
      for (const item of value) {
        const key = JSON.stringify(item);
        if (seen.has(key)) fail(`duplicate item: ${key}`);
        seen.add(key);
      }
    }
    if (schema.items) {
      value.forEach((item, i) => {
        const sub = validateSchema(item, schema.items, `${path}[${i}]`);
        if (!sub.ok) errors.push(...sub.errors);
      });
    }
  }

  if (schema.pattern && typeof value === 'string') {
    const re = new RegExp(schema.pattern);
    if (!re.test(value)) fail(`string "${value}" does not match pattern ${schema.pattern}`);
  }

  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

function loadContract() {
  try {
    return JSON.parse(readFileSync(CONTRACT_PATH, 'utf8'));
  } catch (err) {
    return { __parseError: err.message };
  }
}

function loadSchema() {
  try {
    return JSON.parse(readFileSync(SCHEMA_PATH, 'utf8'));
  } catch (err) {
    return { __parseError: err.message };
  }
}

function flatPermSet(permissions) {
  const flat = new Set();
  for (const perms of Object.values(permissions)) {
    for (const p of perms) flat.add(p);
  }
  return flat;
}

function main() {
  const contract = loadContract();
  const schema = loadSchema();
  const failures = [];

  if (contract.__parseError) {
    failures.push(`permissions.json failed to parse: ${contract.__parseError}`);
  }
  if (schema.__parseError) {
    failures.push(`permissions.schema.json failed to parse: ${schema.__parseError}`);
  }
  if (failures.length) {
    return finish(failures);
  }

  // 1+2: schema validation
  const schemaResult = validateSchema(contract, schema);
  if (!schemaResult.ok) {
    failures.push('permissions.json does not match permissions.schema.json:');
    schemaResult.errors.forEach(e => failures.push(`  - ${e}`));
  }

  // 3: services[] and roles[] unique
  if (new Set(contract.services).size !== contract.services.length) {
    failures.push('services[] contains duplicates');
  }
  if (new Set(contract.roles).size !== contract.roles.length) {
    failures.push('roles[] contains duplicates');
  }

  // 4: closed union — every perm in role_permissions appears in permissions[service]
  const knownPerms = flatPermSet(contract.permissions);
  for (const [role, def] of Object.entries(contract.role_permissions)) {
    for (const perm of def.permissions) {
      if (!knownPerms.has(perm)) {
        failures.push(`role "${role}" references unknown perm "${perm}" (not in any permissions[service] key)`);
      }
    }
  }

  // 5: no duplicate perms within a role
  for (const [role, def] of Object.entries(contract.role_permissions)) {
    if (new Set(def.permissions).size !== def.permissions.length) {
      failures.push(`role "${role}" has duplicate permissions`);
    }
  }

  // 6: every role has >=1 permission
  for (const [role, def] of Object.entries(contract.role_permissions)) {
    if (def.permissions.length === 0) {
      failures.push(`role "${role}" has zero permissions`);
    }
  }

  // 7: helios:tenant:switch is universal (matches HANDOFF — every role)
  const SWITCH = 'helios:tenant:switch';
  for (const role of contract.roles) {
    const def = contract.role_permissions[role];
    if (!def.permissions.includes(SWITCH)) {
      failures.push(`role "${role}" missing universal perm "${SWITCH}"`);
    }
  }

  // 8: helios:tenant:transfer is OWNER-only (ZIN-4714 invariant)
  const TRANSFER = 'helios:tenant:transfer';
  for (const role of contract.roles) {
    const def = contract.role_permissions[role];
    if (role === 'OWNER') {
      if (!def.permissions.includes(TRANSFER)) {
        failures.push(`role "OWNER" missing OWNER-only perm "${TRANSFER}"`);
      }
    } else {
      if (def.permissions.includes(TRANSFER)) {
        failures.push(`role "${role}" has OWNER-only perm "${TRANSFER}" (must be OWNER-only)`);
      }
    }
  }

  finish(failures);
}

function finish(failures) {
  if (failures.length === 0) {
    console.log('✓ permission-contract validates cleanly.');
    process.exit(0);
  }
  console.error('✗ permission-contract validation failed:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

main();
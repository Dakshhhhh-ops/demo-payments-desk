// F6 pre-deploy gate: refuses to pass until every customer record is v2.
//
//   node src/vault-migration-gate.js <export-file> [--allow-empty]
//
// <export-file> holds one sealed customer record per line, exported from the
// customer table after the DBA's re-encryption job. If VAULT_SERVICE_SECRET is
// set, every v2 record must also decrypt with the key derived from it.
// Exit 0: safe to deploy. Exit 1: legacy, invalid or undecryptable records
// remain, or the export is empty. Exit 2: usage error.
import { readFileSync } from 'node:fs';
import { checkVaultMigration, vaultKey } from './vault.js';

const args = process.argv.slice(2);
const allowEmpty = args.includes('--allow-empty');
const file = args.find((a) => !a.startsWith('--'));
if (!file) {
  console.error('usage: node src/vault-migration-gate.js <export-file> [--allow-empty]');
  process.exit(2);
}

const lines = readFileSync(file, 'utf8').split(/\r?\n/).filter((l) => l.trim() !== '');
const secret = process.env.VAULT_SERVICE_SECRET;
const result = checkVaultMigration(lines, { key: secret ? vaultKey(secret) : undefined, allowEmpty });
const { ok, ...counts } = result;
console.log(JSON.stringify({ ...counts, keyChecked: Boolean(secret) }));
if (!ok) {
  console.error('F6 deploy gate: BLOCKED. Every customer record must be v2 (AES-256-GCM) before this release ships.');
  process.exit(1);
}
console.log('F6 deploy gate: passed. All customer records are v2.');

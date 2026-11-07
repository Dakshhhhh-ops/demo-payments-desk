// Customer records at rest.
// Customer profiles (name, phone, address) are encrypted before they are
// written to the database, with a key derived from the service secret.
//
// Format v2 (the only format this module reads or writes):
//   v2.<iv>.<tag>.<ciphertext>   (each part base64)
// AES-256-GCM with a 32-byte key from scrypt, a random 12-byte IV per
// record, and the format label bound in as additional authenticated data.
//
// Records written before v2 (AES-128-GCM, "<iv>.<tag>.<ciphertext>", no
// prefix) are NOT readable here. They are re-encrypted to v2 by the DBA's
// migration before this module is deployed; decryptRecord rejects them with
// an explicit error rather than failing obscurely.
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

export const RECORD_VERSION = 'v2';
const SALT = 'demo-payments/customer-vault/v2';
const AAD = Buffer.from('demo-payments customer-vault v2 record', 'utf8');
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export function vaultKey(serviceSecret) {
  return scryptSync(serviceSecret, SALT, KEY_BYTES);
}

function requireKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new TypeError(`customer vault key must be ${KEY_BYTES} bytes (use vaultKey)`);
  }
}

export function encryptRecord(record, key) {
  requireKey(key);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(AAD);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(record), 'utf8'), cipher.final()]);
  return [RECORD_VERSION, ...[iv, cipher.getAuthTag(), ciphertext].map((b) => b.toString('base64'))].join('.');
}

export function decryptRecord(sealed, key) {
  requireKey(key);
  const parts = String(sealed).split('.');
  if (parts[0] !== RECORD_VERSION) {
    throw new Error('unsupported customer record format: only v2 (AES-256-GCM) records are readable; re-encrypt legacy records first');
  }
  if (parts.length !== 4) throw new Error('malformed v2 customer record');
  const [iv, tag, ciphertext] = parts.slice(1).map((s) => Buffer.from(s, 'base64'));
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new Error('malformed v2 customer record');
  const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(AAD);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
}

// Format of a stored record, judged from its shape alone (no key needed):
// 'v2' for this module's format, 'legacy' for the pre-F6 AES-128-GCM shape
// "<iv>.<tag>.<ciphertext>", 'invalid' for anything else.
export function recordFormat(sealed) {
  const parts = String(sealed).trim().split('.');
  const sizes = (iv, tag) => Buffer.from(iv, 'base64').length === IV_BYTES && Buffer.from(tag, 'base64').length === TAG_BYTES;
  if (parts.length === 4 && parts[0] === RECORD_VERSION && sizes(parts[1], parts[2])) return 'v2';
  if (parts.length === 3 && sizes(parts[0], parts[1])) return 'legacy';
  return 'invalid';
}

// Deploy gate for F6. This module has no AES-128 read path, so it may only be
// deployed once every stored record is v2. Feed it every sealed record from
// the customer table (the DBA's post-migration export). With a key, each v2
// record must also decrypt, which proves the migration wrote it with the
// right key. ok is true only for a non-empty set with no legacy, invalid or
// undecryptable records.
export function checkVaultMigration(sealedRecords, { key, allowEmpty = false } = {}) {
  const result = { total: 0, v2: 0, legacy: 0, invalid: 0, undecryptable: 0 };
  for (const sealed of sealedRecords) {
    result.total += 1;
    const format = recordFormat(sealed);
    result[format] += 1;
    if (format === 'v2' && key) {
      try {
        decryptRecord(String(sealed).trim(), key);
      } catch {
        result.undecryptable += 1;
      }
    }
  }
  result.ok = (result.total > 0 || allowEmpty) && result.legacy === 0 && result.invalid === 0 && result.undecryptable === 0;
  return result;
}

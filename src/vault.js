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

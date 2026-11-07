// Customer records at rest.
// Customer profiles (name, phone, address) are encrypted before they are
// written to the database, with a key derived from the service secret.
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

const SALT = 'demo-payments/customer-vault/v1';

export function vaultKey(serviceSecret) {
  return scryptSync(serviceSecret, SALT, 16);
}

export function encryptRecord(record, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-128-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(record), 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map((b) => b.toString('base64')).join('.');
}

export function decryptRecord(sealed, key) {
  const [iv, tag, ciphertext] = sealed.split('.').map((s) => Buffer.from(s, 'base64'));
  const decipher = createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
}

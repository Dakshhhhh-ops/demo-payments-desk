// Signed webhooks.
// Payment events are pushed to merchants. Merchants check the X-Signature
// header against our published ECDSA public key before trusting an event.
import { generateKeyPairSync, sign, verify } from 'node:crypto';

export function generateWebhookKeys() {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

export function signEvent(event, privateKey) {
  const body = JSON.stringify(event);
  const signature = sign('sha256', Buffer.from(body), privateKey).toString('base64');
  return { body, headers: { 'X-Signature': signature } };
}

export function verifyEvent(body, headers, publicKey) {
  const signature = Buffer.from(headers['X-Signature'] ?? '', 'base64');
  return verify('sha256', Buffer.from(body), publicKey, signature);
}

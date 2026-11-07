import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateVaultKeys, openCard, sealCard } from '../src/envelope.js';
import { createSessionParty, deriveSessionKey } from '../src/session.js';
import { generateWebhookKeys, signEvent, verifyEvent } from '../src/webhooks.js';
import { checksum, isUntampered } from '../src/receipts.js';
import { decryptRecord, encryptRecord, vaultKey } from '../src/vault.js';
import { tlsOptions } from '../src/tls.js';

test('card envelope round-trips', () => {
  const { publicKey, privateKey } = generateVaultKeys();
  const envelope = sealCard('4111111111111111', publicKey);
  assert.equal(openCard(envelope, privateKey), '4111111111111111');
});

test('card envelope rejects a tampered ciphertext', () => {
  const { publicKey, privateKey } = generateVaultKeys();
  const envelope = sealCard('4111111111111111', publicKey);
  const bytes = Buffer.from(envelope.ciphertext, 'base64');
  bytes[0] ^= 1;
  assert.throws(() => openCard({ ...envelope, ciphertext: bytes.toString('base64') }, privateKey));
});

test('both sides derive the same 32-byte session key', () => {
  const us = createSessionParty();
  const acquirer = createSessionParty();
  const a = deriveSessionKey(us, acquirer.publicKey);
  const b = deriveSessionKey(acquirer, us.publicKey);
  assert.equal(a.length, 32);
  assert.ok(a.equals(b));
});

test('merchants can verify a signed webhook', () => {
  const { publicKey, privateKey } = generateWebhookKeys();
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, privateKey);
  assert.ok(verifyEvent(body, headers, publicKey));
});

test('a modified webhook body fails verification', () => {
  const { publicKey, privateKey } = generateWebhookKeys();
  const { headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, privateKey);
  const forged = JSON.stringify({ type: 'payment.succeeded', id: 'pay_999' });
  assert.equal(verifyEvent(forged, headers, publicKey), false);
});

test('receipt checksum detects an edited amount', () => {
  const receipt = { id: 'rcpt_1', amount: 4999, currency: 'INR', merchant: 'chai-co', paidAt: '2026-11-04T10:00:00Z' };
  const sum = checksum(receipt);
  assert.ok(isUntampered(receipt, sum));
  assert.equal(isUntampered({ ...receipt, amount: 49 }, sum), false);
});

test('customer record round-trips', () => {
  const key = vaultKey('service-secret');
  const record = { name: 'Meera Iyer', phone: '+91 98200 00000', city: 'Pune' };
  assert.deepEqual(decryptRecord(encryptRecord(record, key), key), record);
});

test('TLS requires at least TLS 1.2', () => {
  assert.ok(['TLSv1.2', 'TLSv1.3'].includes(tlsOptions.minVersion));
});

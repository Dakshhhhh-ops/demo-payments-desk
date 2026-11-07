import { test } from 'node:test';
import { sign as rawSign, verify as rawVerify } from 'node:crypto';
import assert from 'node:assert/strict';

import { generateVaultKeys, openCard, sealCard } from '../src/envelope.js';
import { createSessionParty, deriveSessionKey } from '../src/session.js';
import { generateWebhookKeys, signEvent, verifyEvent, REPLAY_WINDOW_SECONDS } from '../src/webhooks.js';
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

test('F5: dual-signed webhook verifies with ECDSA and ML-DSA-65', () => {
  const keys = generateWebhookKeys();
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey);
  assert.ok(headers['X-Signature']);
  assert.ok(headers['X-Signature-ML-DSA-65']);
  assert.ok(verifyEvent(body, headers, keys.publicKey, keys.mlDsa.publicKey));
});

test('F5: old SDKs still verify the ECDSA header of a dual-signed webhook', () => {
  const keys = generateWebhookKeys();
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey);
  assert.ok(verifyEvent(body, { 'X-Signature': headers['X-Signature'] }, keys.publicKey));
});

test('F5: legacy ECDSA-only webhook still verifies the old way', () => {
  const keys = generateWebhookKeys();
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey);
  assert.deepEqual(Object.keys(headers), ['X-Signature']);
  assert.ok(verifyEvent(body, headers, keys.publicKey));
});

test('F5: a modified body fails dual verification', () => {
  const keys = generateWebhookKeys();
  const { headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey);
  const forged = JSON.stringify({ type: 'payment.succeeded', id: 'pay_999' });
  assert.equal(verifyEvent(forged, headers, keys.publicKey, keys.mlDsa.publicKey), false);
});

test('F5: stripping or corrupting the ML-DSA header fails when an ML-DSA key is given', () => {
  const keys = generateWebhookKeys();
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey);
  const stripped = { 'X-Signature': headers['X-Signature'] };
  assert.equal(verifyEvent(body, stripped, keys.publicKey, keys.mlDsa.publicKey), false);
  const sig = Buffer.from(headers['X-Signature-ML-DSA-65'], 'base64');
  sig[0] ^= 1;
  const corrupted = { ...headers, 'X-Signature-ML-DSA-65': sig.toString('base64') };
  assert.equal(verifyEvent(body, corrupted, keys.publicKey, keys.mlDsa.publicKey), false);
  assert.equal(verifyEvent(body, { ...headers, 'X-Signature-ML-DSA-65': 'not-a-signature' }, keys.publicKey, keys.mlDsa.publicKey), false);
});

test('F5: a bad ECDSA header fails dual verification even with a valid ML-DSA header', () => {
  const keys = generateWebhookKeys();
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey);
  const other = generateWebhookKeys();
  const wrong = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, other.privateKey).headers['X-Signature'];
  assert.equal(verifyEvent(body, { ...headers, 'X-Signature': wrong }, keys.publicKey, keys.mlDsa.publicKey), false);
});

test('F5: an ML-DSA signature from another key is rejected', () => {
  const keys = generateWebhookKeys();
  const other = generateWebhookKeys();
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, other.mlDsa.privateKey);
  assert.equal(verifyEvent(body, headers, keys.publicKey, keys.mlDsa.publicKey), false);
});

test('F5: signed_at is in the body and covered by both signatures', () => {
  const keys = generateWebhookKeys();
  const now = Date.UTC(2026, 10, 7, 12, 0, 0);
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey, { now });
  assert.equal(JSON.parse(body).signed_at, now / 1000);
  // Old SDK logic: plain ECDSA check over the raw body bytes, unaware of signed_at.
  assert.ok(rawVerify('sha256', Buffer.from(body), keys.publicKey, Buffer.from(headers['X-Signature'], 'base64')));
  assert.ok(rawVerify(null, Buffer.from(body), keys.mlDsa.publicKey, Buffer.from(headers['X-Signature-ML-DSA-65'], 'base64')));
});

test('F5: a fresh event verifies at the edge of the 5-minute window', () => {
  const keys = generateWebhookKeys();
  const now = Date.UTC(2026, 10, 7, 12, 0, 0);
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey, { now });
  const atEdge = now + REPLAY_WINDOW_SECONDS * 1000;
  assert.ok(verifyEvent(body, headers, keys.publicKey, keys.mlDsa.publicKey, { now: atEdge }));
  assert.ok(verifyEvent(body, headers, keys.publicKey, undefined, { now: atEdge }));
});

test('F5: an expired event is rejected on both verify paths', () => {
  const keys = generateWebhookKeys();
  const now = Date.UTC(2026, 10, 7, 12, 0, 0);
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey, { now });
  const late = now + (REPLAY_WINDOW_SECONDS + 1) * 1000;
  assert.equal(verifyEvent(body, headers, keys.publicKey, keys.mlDsa.publicKey, { now: late }), false);
  assert.equal(verifyEvent(body, headers, keys.publicKey, undefined, { now: late }), false);
});

test('F5: an event dated too far in the future is rejected', () => {
  const keys = generateWebhookKeys();
  const now = Date.UTC(2026, 10, 7, 12, 0, 0);
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey, { now: now + 120_000 });
  assert.equal(verifyEvent(body, headers, keys.publicKey, keys.mlDsa.publicKey, { now }), false);
});

test('F5: a tampered signed_at fails both signatures', () => {
  const keys = generateWebhookKeys();
  const old = Date.UTC(2026, 10, 7, 12, 0, 0);
  const { body, headers } = signEvent({ type: 'payment.succeeded', id: 'pay_123' }, keys.privateKey, keys.mlDsa.privateKey, { now: old });
  const now = old + 3600_000;
  const refreshed = JSON.stringify({ ...JSON.parse(body), signed_at: now / 1000 });
  assert.equal(verifyEvent(refreshed, headers, keys.publicKey, keys.mlDsa.publicKey, { now }), false);
  assert.equal(verifyEvent(refreshed, headers, keys.publicKey, undefined, { now }), false);
});

test('F5: signed_at from the caller cannot override our clock', () => {
  const keys = generateWebhookKeys();
  const now = Date.UTC(2026, 10, 7, 12, 0, 0);
  const { body } = signEvent({ type: 'payment.succeeded', id: 'pay_123', signed_at: 1 }, keys.privateKey, keys.mlDsa.privateKey, { now });
  assert.equal(JSON.parse(body).signed_at, now / 1000);
});

test('F5: a pre-F5 body-only event (no signed_at) has no replay protection and is rejected', () => {
  const keys = generateWebhookKeys();
  const body = JSON.stringify({ type: 'payment.succeeded', id: 'pay_123' });
  const headers = { 'X-Signature': rawSign('sha256', Buffer.from(body), keys.privateKey).toString('base64') };
  // The old header format is still a valid ECDSA signature for old SDK logic...
  assert.ok(rawVerify('sha256', Buffer.from(body), keys.publicKey, Buffer.from(headers['X-Signature'], 'base64')));
  // ...but our verifier requires a signed timestamp.
  assert.equal(verifyEvent(body, headers, keys.publicKey), false);
  assert.equal(verifyEvent('not json', headers, keys.publicKey), false);
});

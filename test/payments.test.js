import { test } from 'node:test';
import {
  constants,
  createCipheriv,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes,
  sign as rawSign,
  verify as rawVerify,
} from 'node:crypto';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import tls from 'node:tls';

import {
  ENVELOPE_ALG,
  envelopeVersion,
  generateVaultKeys,
  openCard,
  resealCard,
  sealCard,
} from '../src/envelope.js';
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

// The v1 sealer exactly as it shipped before F1, so the tests read real
// legacy envelopes rather than ones made by the new code.
function sealCardV1(cardNumber, rsaPublicKey) {
  const dataKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
  const ciphertext = Buffer.concat([cipher.update(cardNumber, 'utf8'), cipher.final()]);
  const wrappedKey = publicEncrypt(
    { key: rsaPublicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    dataKey,
  );
  return {
    wrappedKey: wrappedKey.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function flipFirstByte(b64) {
  const bytes = Buffer.from(b64, 'base64');
  bytes[0] ^= 1;
  return bytes.toString('base64');
}

test('new card envelopes are v2 hybrid X25519 + ML-KEM-768 with no RSA wrap', () => {
  const { publicKey } = generateVaultKeys();
  const envelope = sealCard('4111111111111111', publicKey);
  assert.equal(envelope.v, 2);
  assert.equal(envelope.alg, ENVELOPE_ALG);
  assert.equal(envelope.wrappedKey, undefined);
  assert.equal(Buffer.from(envelope.kemCiphertext, 'base64').length, 1088); // ML-KEM-768 ciphertext
  assert.equal(Buffer.from(envelope.iv, 'base64').length, 12);
});

test('two envelopes for the same card share no IV, KEM ciphertext or ephemeral key', () => {
  const { publicKey } = generateVaultKeys();
  const a = sealCard('4111111111111111', publicKey);
  const b = sealCard('4111111111111111', publicKey);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.kemCiphertext, b.kemCiphertext);
  assert.notEqual(a.ephemeralKey, b.ephemeralKey);
  assert.notEqual(a.ciphertext, b.ciphertext);
});

for (const field of ['kemCiphertext', 'ephemeralKey', 'iv', 'tag']) {
  test(`card envelope rejects a tampered ${field}`, () => {
    const { publicKey, privateKey } = generateVaultKeys();
    const envelope = sealCard('4111111111111111', publicKey);
    assert.throws(() => openCard({ ...envelope, [field]: flipFirstByte(envelope[field]) }, privateKey));
  });
}

test('card envelope rejects a changed version or algorithm label', () => {
  const { publicKey, privateKey } = generateVaultKeys();
  const envelope = sealCard('4111111111111111', publicKey);
  assert.throws(() => openCard({ ...envelope, v: 3 }, privateKey), /unsupported envelope version/);
  assert.throws(() => openCard({ ...envelope, alg: 'RSA-OAEP' }, privateKey), /unsupported envelope algorithm/);
});

test('a v2 envelope does not open with another vault key', () => {
  const vault = generateVaultKeys();
  const other = generateVaultKeys();
  const envelope = sealCard('4111111111111111', vault.publicKey);
  assert.throws(() => openCard(envelope, other.privateKey));
  // Either half alone being wrong is enough to fail.
  assert.throws(() => openCard(envelope, { ...vault.privateKey, mlkem: other.privateKey.mlkem }));
  assert.throws(() => openCard(envelope, { ...vault.privateKey, x25519: other.privateKey.x25519 }));
});

test('sealCard refuses a bare RSA public key', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.throws(() => sealCard('4111111111111111', rsa.publicKey), /X25519 and ML-KEM-768/);
});

test('legacy v1 RSA-OAEP envelopes still open', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const vault = generateVaultKeys();
  const legacy = sealCardV1('4111111111111111', rsa.publicKey);
  assert.equal(envelopeVersion(legacy), 1);
  assert.equal(openCard(legacy, { ...vault.privateKey, rsa: rsa.privateKey }), '4111111111111111');
  assert.throws(() => openCard(legacy, vault.privateKey), /legacy RSA private key/);
});

test('legacy v1 envelope still rejects a tampered ciphertext', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const legacy = sealCardV1('4111111111111111', rsa.publicKey);
  assert.throws(() => openCard({ ...legacy, ciphertext: flipFirstByte(legacy.ciphertext) }, { rsa: rsa.privateKey }));
});

test('resealCard turns a v1 envelope into a v2 one that opens without RSA', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const vault = generateVaultKeys();
  const legacy = sealCardV1('5555555555554444', rsa.publicKey);
  const resealed = resealCard(legacy, { ...vault.privateKey, rsa: rsa.privateKey }, vault.publicKey);
  assert.equal(envelopeVersion(resealed), 2);
  assert.equal(openCard(resealed, vault.privateKey), '5555555555554444');
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

// F3: TLS key exchange. Real loopback handshakes against tlsOptions.
// The fixture key and certificate are test-only (Ed25519, CN=localhost).
const tlsFixtures = new URL('./fixtures/', import.meta.url);
const tlsKey = readFileSync(new URL('tls-test-key.pem', tlsFixtures));
const tlsCert = readFileSync(new URL('tls-test-cert.pem', tlsFixtures));

async function handshake(clientOptions) {
  const server = tls.createServer({ ...tlsOptions, key: tlsKey, cert: tlsCert }, (s) => s.end());
  server.on('tlsClientError', () => {});
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    return await new Promise((resolve) => {
      const socket = tls.connect(
        { host: '127.0.0.1', port: server.address().port, servername: 'localhost', ca: tlsCert, ...clientOptions },
        () => {
          const result = { ok: true, protocol: socket.getProtocol(), keyInfo: socket.getEphemeralKeyInfo() };
          socket.destroy();
          resolve(result);
        },
      );
      socket.on('error', (err) => resolve({ ok: false, code: err.code }));
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('F3: TLS options offer X25519MLKEM768 first, X25519 as fallback, TLS 1.3 only', () => {
  assert.equal(tlsOptions.minVersion, 'TLSv1.3');
  assert.deepEqual(tlsOptions.ecdhCurve.split(':'), ['X25519MLKEM768', 'X25519']);
});

test('F3: a client offering only X25519MLKEM768 completes a TLS 1.3 handshake', async () => {
  const r = await handshake({ ecdhCurve: 'X25519MLKEM768' });
  assert.equal(r.ok, true, `handshake failed: ${r.code}`);
  assert.equal(r.protocol, 'TLSv1.3');
});

test('F3: a client offering hybrid then X25519 does not settle on X25519', async () => {
  const r = await handshake({ ecdhCurve: 'X25519MLKEM768:X25519' });
  assert.equal(r.ok, true, `handshake failed: ${r.code}`);
  assert.notEqual(r.keyInfo?.name, 'X25519');
});

test('F3: an X25519-only client falls back to X25519', async () => {
  const r = await handshake({ ecdhCurve: 'X25519' });
  assert.equal(r.ok, true, `handshake failed: ${r.code}`);
  assert.equal(r.protocol, 'TLSv1.3');
  assert.equal(r.keyInfo.name, 'X25519');
});

test('F3: a P-256-only client is refused', async () => {
  const r = await handshake({ ecdhCurve: 'prime256v1' });
  assert.equal(r.ok, false);
});

test('F3: a TLS 1.2 client is refused', async () => {
  const r = await handshake({ maxVersion: 'TLSv1.2' });
  assert.equal(r.ok, false);
});

// Receipt integrity.
// Every receipt carries a checksum so support staff can confirm that a
// receipt a customer forwards has not been edited.
//
// Formats
//   v2 (current): "v2." + hex HMAC-SHA-256 over a domain tag and the
//       canonical receipt, keyed by a server secret. Without the key a
//       customer cannot produce a matching checksum for an edited receipt.
//   v1 (legacy, read only): bare 40-hex SHA-1 of the canonical receipt.
//       Unkeyed and collision-prone. Accepted only so that receipts already
//       issued still verify; results are flagged `legacy: true`. New
//       checksums are never v1. Sunset: remove the v1 read path once the
//       last v1 receipt is past the receipt retention period (date to be
//       set by the receipts owner).
//
// Key: pass `key` explicitly, or set RECEIPT_CHECKSUM_KEY. At least 32 bytes.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const CHECKSUM_VERSION = 'v2';
const DOMAIN = 'demo-payments/receipt-checksum/v2\n';
const MIN_KEY_BYTES = 32;
const V2_PATTERN = /^v2\.[0-9a-f]{64}$/;
const V1_PATTERN = /^[0-9a-f]{40}$/;

function canonical(receipt) {
  return JSON.stringify({
    id: receipt.id,
    amount: receipt.amount,
    currency: receipt.currency,
    merchant: receipt.merchant,
    paidAt: receipt.paidAt,
  });
}

function resolveKey(key) {
  const raw = key ?? process.env.RECEIPT_CHECKSUM_KEY;
  if (raw === undefined || raw === null || raw === '') {
    throw new Error('receipt checksum key missing: pass a key or set RECEIPT_CHECKSUM_KEY');
  }
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), 'utf8');
  if (buf.length < MIN_KEY_BYTES) {
    throw new Error(`receipt checksum key must be at least ${MIN_KEY_BYTES} bytes`);
  }
  return buf;
}

function hmacHex(receipt, key) {
  return createHmac('sha256', key).update(DOMAIN).update(canonical(receipt)).digest('hex');
}

function legacySha1Hex(receipt) {
  return createHash('sha1').update(canonical(receipt)).digest('hex');
}

function equalHex(a, b) {
  const x = Buffer.from(a, 'hex');
  const y = Buffer.from(b, 'hex');
  return x.length === y.length && timingSafeEqual(x, y);
}

export function checksum(receipt, key) {
  return `${CHECKSUM_VERSION}.${hmacHex(receipt, resolveKey(key))}`;
}

// Returns { ok, legacy }. `legacy` is true when a v1 SHA-1 checksum matched;
// callers should treat that as weaker evidence and re-issue with checksum().
export function verifyReceipt(receipt, expected, { key, acceptLegacy = true } = {}) {
  if (typeof expected !== 'string') return { ok: false, legacy: false };
  if (V2_PATTERN.test(expected)) {
    return { ok: equalHex(hmacHex(receipt, resolveKey(key)), expected.slice(3)), legacy: false };
  }
  if (V1_PATTERN.test(expected)) {
    if (!acceptLegacy) return { ok: false, legacy: true };
    return { ok: equalHex(legacySha1Hex(receipt), expected), legacy: true };
  }
  return { ok: false, legacy: false };
}

export function isUntampered(receipt, expected, options) {
  return verifyReceipt(receipt, expected, options).ok;
}

// Re-issue a verified legacy checksum as v2. Throws if the old one does not match.
export function upgradeChecksum(receipt, expected, key) {
  const result = verifyReceipt(receipt, expected, { key });
  if (!result.ok) throw new Error('receipt does not match its checksum; refusing to upgrade');
  return result.legacy ? checksum(receipt, key) : expected;
}

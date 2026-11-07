// Receipt integrity.
// Every receipt carries a checksum so support staff can confirm that a
// receipt a customer forwards has not been edited.
//
// Formats
//   v2 (current): "v2." + hex HMAC-SHA-256 over a domain tag and the
//       canonical receipt, keyed by a server secret. Without the key a
//       customer cannot produce a matching checksum for an edited receipt.
//   v1 (retired): bare 40-hex SHA-1 of the canonical receipt. No longer
//       verified at all: it is unkeyed and collision-prone. A v1 checksum is
//       rejected without being hashed and flagged `legacy: true`, so support
//       knows to re-issue the receipt as v2 from our own records with
//       checksum() rather than trust the forwarded copy.
//
// Key: pass `key` explicitly, or set RECEIPT_CHECKSUM_KEY. At least 32 bytes.
import { createHmac, timingSafeEqual } from 'node:crypto';

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

function equalHex(a, b) {
  const x = Buffer.from(a, 'hex');
  const y = Buffer.from(b, 'hex');
  return x.length === y.length && timingSafeEqual(x, y);
}

export function checksum(receipt, key) {
  return `${CHECKSUM_VERSION}.${hmacHex(receipt, resolveKey(key))}`;
}

// Returns { ok, legacy }. `legacy` is true when `expected` has the retired v1
// shape; it is never ok, and support should re-issue from records.
export function verifyReceipt(receipt, expected, { key } = {}) {
  if (typeof expected !== 'string') return { ok: false, legacy: false };
  if (V2_PATTERN.test(expected)) {
    return { ok: equalHex(hmacHex(receipt, resolveKey(key)), expected.slice(3)), legacy: false };
  }
  if (V1_PATTERN.test(expected)) return { ok: false, legacy: true };
  return { ok: false, legacy: false };
}

export function isUntampered(receipt, expected, options) {
  return verifyReceipt(receipt, expected, options).ok;
}


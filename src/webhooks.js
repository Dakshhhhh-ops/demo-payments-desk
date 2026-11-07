// Signed webhooks.
// Payment events are pushed to merchants, who check the signatures against
// our published public keys before trusting an event.
//
// Dual signatures (finding F5):
//   X-Signature            ECDSA P-256 / SHA-256, base64. Unchanged, for
//                          merchants on older SDKs that only understand it.
//                          SUNSET: 30 June 2027. After that date we stop
//                          sending this header.
//   X-Signature-ML-DSA-65  ML-DSA-65 (FIPS 204), base64, over the same body
//                          bytes. Post-quantum signature that every SDK must
//                          verify by the sunset date.
//
// Replay window: the body carries `signed_at` (Unix seconds), so both
// signatures cover it. Old SDKs ignore unknown JSON fields and keep verifying
// X-Signature byte-for-byte. verifyEvent rejects events older than 5 minutes,
// events dated more than 60 seconds in the future (clock-skew allowance), and
// events without a valid signed_at.
import { generateKeyPairSync, sign, verify } from 'node:crypto';

export const ECDSA_HEADER = 'X-Signature';
export const ML_DSA_HEADER = 'X-Signature-ML-DSA-65';
export const ECDSA_SUNSET = '2027-06-30';
export const REPLAY_WINDOW_SECONDS = 5 * 60;
export const MAX_CLOCK_SKEW_SECONDS = 60;

// Returns the ECDSA pair as { publicKey, privateKey } (as before) plus the
// ML-DSA-65 pair under `mlDsa`.
export function generateWebhookKeys() {
  const ecdsa = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const mlDsa = generateKeyPairSync('ml-dsa-65');
  return { publicKey: ecdsa.publicKey, privateKey: ecdsa.privateKey, mlDsa };
}

// privateKey: ECDSA private key. mlDsaPrivateKey (optional): ML-DSA-65
// private key; when given, the ML-DSA header is added. options.now: clock in
// milliseconds (default Date.now()). signed_at always reflects our clock and
// overrides any signed_at the caller put in the event.
export function signEvent(event, privateKey, mlDsaPrivateKey, { now = Date.now() } = {}) {
  const body = JSON.stringify({ ...event, signed_at: Math.floor(now / 1000) });
  const bytes = Buffer.from(body);
  const headers = {
    [ECDSA_HEADER]: sign('sha256', bytes, privateKey).toString('base64'),
  };
  if (mlDsaPrivateKey) {
    headers[ML_DSA_HEADER] = sign(null, bytes, mlDsaPrivateKey).toString('base64');
  }
  return { body, headers };
}

function checkSignature(algorithm, bytes, publicKey, encoded) {
  if (typeof encoded !== 'string' || encoded === '') return false;
  try {
    return verify(algorithm, bytes, publicKey, Buffer.from(encoded, 'base64'));
  } catch {
    return false;
  }
}

function isFresh(body, now) {
  let signedAt;
  try {
    signedAt = JSON.parse(body)?.signed_at;
  } catch {
    return false;
  }
  if (!Number.isSafeInteger(signedAt)) return false;
  const age = Math.floor(now / 1000) - signedAt;
  return age <= REPLAY_WINDOW_SECONDS && age >= -MAX_CLOCK_SKEW_SECONDS;
}

// publicKey: ECDSA public key. mlDsaPublicKey (optional): when given, a valid
// ML-DSA-65 signature is REQUIRED, so stripping that header cannot downgrade
// the check to ECDSA only. While dual-signing, the ECDSA signature must also
// be valid. Without mlDsaPublicKey this is the legacy ECDSA-only check.
// Either way the signed signed_at must fall inside the replay window.
// options.now: clock in milliseconds (default Date.now()).
export function verifyEvent(body, headers, publicKey, mlDsaPublicKey, { now = Date.now() } = {}) {
  const bytes = Buffer.from(body);
  if (!checkSignature('sha256', bytes, publicKey, headers[ECDSA_HEADER])) return false;
  if (mlDsaPublicKey && !checkSignature(null, bytes, mlDsaPublicKey, headers[ML_DSA_HEADER])) {
    return false;
  }
  return isFresh(body, now);
}

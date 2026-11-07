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
import { generateKeyPairSync, sign, verify } from 'node:crypto';

export const ECDSA_HEADER = 'X-Signature';
export const ML_DSA_HEADER = 'X-Signature-ML-DSA-65';
export const ECDSA_SUNSET = '2027-06-30';

// Returns the ECDSA pair as { publicKey, privateKey } (as before) plus the
// ML-DSA-65 pair under `mlDsa`.
export function generateWebhookKeys() {
  const ecdsa = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const mlDsa = generateKeyPairSync('ml-dsa-65');
  return { publicKey: ecdsa.publicKey, privateKey: ecdsa.privateKey, mlDsa };
}

// privateKey: ECDSA private key. mlDsaPrivateKey (optional): ML-DSA-65
// private key; when given, the ML-DSA header is added.
export function signEvent(event, privateKey, mlDsaPrivateKey) {
  const body = JSON.stringify(event);
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

// publicKey: ECDSA public key. mlDsaPublicKey (optional): when given, a valid
// ML-DSA-65 signature is REQUIRED, so stripping that header cannot downgrade
// the check to ECDSA only. While dual-signing, the ECDSA signature must also
// be valid. Without mlDsaPublicKey this is the legacy ECDSA-only check.
export function verifyEvent(body, headers, publicKey, mlDsaPublicKey) {
  const bytes = Buffer.from(body);
  if (!checkSignature('sha256', bytes, publicKey, headers[ECDSA_HEADER])) return false;
  if (mlDsaPublicKey) {
    return checkSignature(null, bytes, mlDsaPublicKey, headers[ML_DSA_HEADER]);
  }
  return true;
}

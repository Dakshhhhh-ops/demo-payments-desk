// Partner session keys.
// The service and an acquirer partner agree a shared session key, then use
// it to encrypt settlement files sent between them. Both ends run this file:
// the acquirer's settlement client is built from this repo.
//
// v2 handshake: hybrid X25519 + ML-KEM-768 (FIPS 203).
//   1. Responder: createSessionOffer() -> sends `offer` (an X25519 public key
//      and an ML-KEM-768 encapsulation key), keeps `state` private.
//   2. Initiator: acceptSessionOffer(offer) -> gets the session key, sends
//      `reply` (its own X25519 public key and the ML-KEM ciphertext).
//   3. Responder: completeSession(state, reply) -> gets the same session key.
// Both shared secrets go through HKDF-SHA-256, salted with a hash of the
// whole handshake transcript, so the key stays safe while either half holds.
//
// The v1 handshake (ECDH P-256, SHA-256 of the raw secret) was removed with
// no fallback: both ends switch together, and settlement files are decrypted
// on arrival, so no stored data depends on v1 keys. Messages that are not v2
// are rejected.
import {
  createHash,
  createPublicKey,
  decapsulate,
  diffieHellman,
  encapsulate,
  generateKeyPairSync,
  hkdfSync,
} from 'node:crypto';

export const SESSION_VERSION = 2;
export const SESSION_ALG = 'X25519-MLKEM768-HKDF-SHA256';
const HKDF_INFO = 'demo-payments partner-settlement session v2 key';
const MLKEM768_CIPHERTEXT_BYTES = 1088;

function spki(key) {
  return key.export({ format: 'der', type: 'spki' });
}

function importPublic(b64, expectedType, field) {
  if (typeof b64 !== 'string') throw new TypeError(`session message is missing ${field}`);
  const der = Buffer.from(b64, 'base64');
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== expectedType) {
    throw new Error(`session ${field} is not an ${expectedType} key`);
  }
  return { key, der };
}

function checkHeader(message, kind) {
  if (!message || message.v !== SESSION_VERSION) {
    throw new Error(`unsupported session ${kind} version: ${message?.v}`);
  }
  if (message.alg !== SESSION_ALG) {
    throw new Error(`unsupported session ${kind} algorithm: ${message.alg}`);
  }
}

function deriveKey({ x25519Secret, mlkemSecret, offerX25519, offerMlkem, replyX25519, kemCiphertext }) {
  if (x25519Secret.every((b) => b === 0)) {
    throw new Error('X25519 shared secret is all zero (low-order peer key)');
  }
  const salt = createHash('sha256')
    .update(`v${SESSION_VERSION}:${SESSION_ALG}`)
    .update(offerX25519)
    .update(offerMlkem)
    .update(replyX25519)
    .update(kemCiphertext)
    .digest();
  const ikm = Buffer.concat([mlkemSecret, x25519Secret]);
  return Buffer.from(hkdfSync('sha256', ikm, salt, HKDF_INFO, 32));
}

// Responder, step 1. Use a fresh offer for every session.
export function createSessionOffer() {
  const x25519 = generateKeyPairSync('x25519');
  const mlkem = generateKeyPairSync('ml-kem-768');
  const offerX25519 = spki(x25519.publicKey);
  const offerMlkem = spki(mlkem.publicKey);
  return {
    state: { x25519: x25519.privateKey, mlkem: mlkem.privateKey, offerX25519, offerMlkem },
    offer: {
      v: SESSION_VERSION,
      alg: SESSION_ALG,
      x25519: offerX25519.toString('base64'),
      mlkem: offerMlkem.toString('base64'),
    },
  };
}

// Initiator, step 2. Returns the session key and the reply to send back.
export function acceptSessionOffer(offer) {
  checkHeader(offer, 'offer');
  const peerX25519 = importPublic(offer.x25519, 'x25519', 'x25519');
  const peerMlkem = importPublic(offer.mlkem, 'ml-kem-768', 'mlkem');

  const ephemeral = generateKeyPairSync('x25519');
  const x25519Secret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: peerX25519.key });
  const { sharedKey: mlkemSecret, ciphertext: kemCiphertext } = encapsulate(peerMlkem.key);
  const replyX25519 = spki(ephemeral.publicKey);

  const key = deriveKey({
    x25519Secret,
    mlkemSecret,
    offerX25519: peerX25519.der,
    offerMlkem: peerMlkem.der,
    replyX25519,
    kemCiphertext,
  });
  return {
    key,
    reply: {
      v: SESSION_VERSION,
      alg: SESSION_ALG,
      x25519: replyX25519.toString('base64'),
      kemCiphertext: kemCiphertext.toString('base64'),
    },
  };
}

// Responder, step 3. Returns the same session key as the initiator.
export function completeSession(state, reply) {
  checkHeader(reply, 'reply');
  const peerX25519 = importPublic(reply.x25519, 'x25519', 'x25519');
  if (typeof reply.kemCiphertext !== 'string') throw new TypeError('session reply is missing kemCiphertext');
  const kemCiphertext = Buffer.from(reply.kemCiphertext, 'base64');
  if (kemCiphertext.length !== MLKEM768_CIPHERTEXT_BYTES) {
    throw new Error(`ML-KEM-768 ciphertext must be ${MLKEM768_CIPHERTEXT_BYTES} bytes`);
  }

  const x25519Secret = diffieHellman({ privateKey: state.x25519, publicKey: peerX25519.key });
  const mlkemSecret = decapsulate(state.mlkem, kemCiphertext);
  return deriveKey({
    x25519Secret,
    mlkemSecret,
    offerX25519: state.offerX25519,
    offerMlkem: state.offerMlkem,
    replyX25519: peerX25519.der,
    kemCiphertext,
  });
}

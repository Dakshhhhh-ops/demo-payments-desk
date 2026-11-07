// Card vault envelope encryption.
//
// v2 (written by sealCard): each card is encrypted with AES-256-GCM under a
// key derived for that envelope alone. The key comes from a hybrid key
// encapsulation to the vault: an ephemeral X25519 exchange with the vault's
// X25519 key plus an ML-KEM-768 (FIPS 203) encapsulation to the vault's
// ML-KEM key. Both shared secrets are combined with HKDF-SHA-256, so the
// key stays safe while either half holds.
//
// v1 (legacy, read only): the data key was wrapped with the vault's RSA-OAEP
// 2048 public key. Those envelopes have no `v` field. openCard still reads
// them so stored cards stay readable; resealCard rewrites them as v2. Once
// no v1 envelope is left, the v1 path and the RSA key are to be removed
// (see infra/DEPLOY.md).
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  decapsulate,
  diffieHellman,
  encapsulate,
  generateKeyPairSync,
  hkdfSync,
  KeyObject,
  privateDecrypt,
  randomBytes,
} from 'node:crypto';

export const ENVELOPE_VERSION = 2;
export const ENVELOPE_ALG = 'X25519-MLKEM768-HKDF-SHA256-A256GCM';
const HKDF_INFO = 'demo-payments card-vault envelope v2 data key';

// The vault's v2 keys. publicKey is what sealCard needs; privateKey is what
// openCard needs. Each holds an X25519 half and an ML-KEM-768 half.
export function generateVaultKeys() {
  const x25519 = generateKeyPairSync('x25519');
  const mlkem = generateKeyPairSync('ml-kem-768');
  return {
    publicKey: { x25519: x25519.publicKey, mlkem: mlkem.publicKey },
    privateKey: { x25519: x25519.privateKey, mlkem: mlkem.privateKey },
  };
}

function asPublicKey(key) {
  return key instanceof KeyObject && key.type === 'public' ? key : createPublicKey(key);
}

function spki(key) {
  return key.export({ format: 'der', type: 'spki' });
}

function aad() {
  return Buffer.from(`v${ENVELOPE_VERSION}:${ENVELOPE_ALG}`, 'utf8');
}

// HKDF-SHA-256 over both shared secrets. The salt is a hash of the
// ephemeral X25519 key, the vault's X25519 key and the ML-KEM ciphertext,
// so the derived key is bound to this envelope's exchange.
function deriveDataKey({ mlkemSecret, x25519Secret, ephemeralPub, vaultX25519Pub, kemCiphertext }) {
  const salt = createHash('sha256')
    .update(ephemeralPub)
    .update(vaultX25519Pub)
    .update(kemCiphertext)
    .digest();
  const ikm = Buffer.concat([mlkemSecret, x25519Secret]);
  return Buffer.from(hkdfSync('sha256', ikm, salt, HKDF_INFO, 32));
}

function requireV2Keys(keys, which) {
  if (!keys || !keys.x25519 || !keys.mlkem) {
    throw new TypeError(`v2 envelopes need the vault's X25519 and ML-KEM-768 ${which} keys`);
  }
}

export function sealCard(cardNumber, vaultPublicKey) {
  requireV2Keys(vaultPublicKey, 'public');
  const vaultX25519Pub = asPublicKey(vaultPublicKey.x25519);

  const ephemeral = generateKeyPairSync('x25519');
  const x25519Secret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: vaultX25519Pub });
  const { sharedKey: mlkemSecret, ciphertext: kemCiphertext } = encapsulate(vaultPublicKey.mlkem);

  const ephemeralPub = spki(ephemeral.publicKey);
  const dataKey = deriveDataKey({
    mlkemSecret,
    x25519Secret,
    ephemeralPub,
    vaultX25519Pub: spki(vaultX25519Pub),
    kemCiphertext,
  });

  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
  cipher.setAAD(aad());
  const ciphertext = Buffer.concat([cipher.update(cardNumber, 'utf8'), cipher.final()]);

  return {
    v: ENVELOPE_VERSION,
    alg: ENVELOPE_ALG,
    ephemeralKey: ephemeralPub.toString('base64'),
    kemCiphertext: kemCiphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function openV2(envelope, vaultPrivateKey) {
  requireV2Keys(vaultPrivateKey, 'private');
  if (envelope.alg !== ENVELOPE_ALG) {
    throw new Error(`unsupported envelope algorithm: ${envelope.alg}`);
  }
  const ephemeralPub = Buffer.from(envelope.ephemeralKey, 'base64');
  const kemCiphertext = Buffer.from(envelope.kemCiphertext, 'base64');
  const ephemeralKey = createPublicKey({ key: ephemeralPub, format: 'der', type: 'spki' });
  if (ephemeralKey.asymmetricKeyType !== 'x25519') {
    throw new Error('envelope ephemeral key is not X25519');
  }

  const x25519Secret = diffieHellman({ privateKey: vaultPrivateKey.x25519, publicKey: ephemeralKey });
  const mlkemSecret = decapsulate(vaultPrivateKey.mlkem, kemCiphertext);
  const dataKey = deriveDataKey({
    mlkemSecret,
    x25519Secret,
    ephemeralPub,
    vaultX25519Pub: spki(asPublicKey(vaultPrivateKey.x25519)),
    kemCiphertext,
  });

  const decipher = createDecipheriv('aes-256-gcm', dataKey, Buffer.from(envelope.iv, 'base64'));
  decipher.setAAD(aad());
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

// Legacy read path for v1 (RSA-OAEP-wrapped) envelopes. Read only.
function openV1(envelope, rsaPrivateKey) {
  if (!rsaPrivateKey) {
    throw new TypeError('v1 envelopes need the legacy RSA private key (pass it as keys.rsa)');
  }
  const dataKey = privateDecrypt(
    { key: rsaPrivateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(envelope.wrappedKey, 'base64'),
  );
  const decipher = createDecipheriv('aes-256-gcm', dataKey, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

export function envelopeVersion(envelope) {
  return envelope.v === undefined ? 1 : envelope.v;
}

// vaultPrivateKey is the v2 private key object from generateVaultKeys. To
// read v1 envelopes, add the legacy RSA private key as `rsa`.
export function openCard(envelope, vaultPrivateKey) {
  const version = envelopeVersion(envelope);
  if (version === 2) return openV2(envelope, vaultPrivateKey);
  if (version === 1) return openV1(envelope, vaultPrivateKey?.rsa);
  throw new Error(`unsupported envelope version: ${version}`);
}

// Re-encryption pass: opens any envelope (v1 or v2) and seals it again as v2.
export function resealCard(envelope, vaultPrivateKey, vaultPublicKey) {
  return sealCard(openCard(envelope, vaultPrivateKey), vaultPublicKey);
}

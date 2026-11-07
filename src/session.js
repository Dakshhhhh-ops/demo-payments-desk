// Partner session keys.
// The service and an acquirer partner agree a shared session key with ECDH,
// then use it to encrypt settlement files sent between them.
import { createECDH, createHash } from 'node:crypto';

export function createSessionParty() {
  const ecdh = createECDH('prime256v1');
  const publicKey = ecdh.generateKeys();
  return { ecdh, publicKey };
}

export function deriveSessionKey(party, peerPublicKey) {
  const secret = party.ecdh.computeSecret(peerPublicKey);
  return createHash('sha256').update(secret).digest();
}

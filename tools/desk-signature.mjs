// Signed desk actions: what the reviewer approved and what the shipper
// merged, signed with ML-DSA-65 by that agent's key and checked by the gate.
//
// A signed action is a block of "key value" lines inside a git message (an
// annotated tag's message for an approval, a commit message for a ship or an
// accepted risk), followed by the signature line:
//
//   desk approve                 desk ship                desk accept
//   commit <sha>                 finding F5               finding F3
//   room <switch room id>        base <main before>       parent <main before>
//   role reviewer                fix <approved sha>       room <switch room id>
//   agent desk4-reviewer         room <switch room id>    ordered-by <owner>
//                                ordered-by <owner>       order-at <timestamp>
//                                order-at <timestamp>     order-text <the order>
//                                order-text <the order, verbatim>
//   Desk-Signature: ML-DSA-65 <base64 signature over the lines above it>
//
// The room, role and agent, and who ordered the ship, when and in what words,
// come from Switch (the room the agent works in, and the owner's message in
// its history), so the git record names the Switch facts that allowed each
// step. A judge finds the order in the room by its time and text.
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const KINDS = ['approve', 'ship', 'accept'];
export const ROLES = { approve: 'reviewer', ship: 'shipper', accept: 'shipper' };
const SIG = 'Desk-Signature: ML-DSA-65 ';
const FIELD_ORDER = {
  approve: ['commit', 'room', 'role', 'agent'],
  ship: ['finding', 'base', 'fix', 'room', 'ordered-by', 'order-at', 'order-text'],
  accept: ['finding', 'parent', 'room', 'ordered-by', 'order-at', 'order-text'],
};

// The lines that get signed. Empty fields are left out.
export function payload(kind, fields) {
  const lines = [`desk ${kind}`];
  for (const k of FIELD_ORDER[kind]) {
    const v = fields[k];
    if (v === undefined || v === null || v === '') continue;
    if (/[\r\n]/.test(String(v))) throw new Error(`${k} must be one line`);
    lines.push(`${k} ${String(v).trim()}`);
  }
  return lines.join('\n');
}

export function signedBlock(kind, fields, privateKeyPem) {
  const text = payload(kind, fields);
  const value = sign(null, Buffer.from(text), createPrivateKey(privateKeyPem)).toString('base64');
  return `${text}\n${SIG}${value}`;
}

// The signed block in a git message, or null if it has none.
export function parseSigned(message) {
  const lines = message.split(/\r?\n/);
  const start = lines.findIndex((l) => KINDS.some((k) => l.trim() === `desk ${k}`));
  if (start < 0) return null;
  const end = lines.findIndex((l, i) => i > start && l.startsWith(SIG));
  if (end < 0) return { kind: lines[start].trim().slice(5), fields: {}, payload: null, signature: null };
  const block = lines.slice(start, end).map((l) => l.trimEnd());
  const fields = {};
  for (const l of block.slice(1)) {
    const at = l.indexOf(' ');
    if (at > 0) fields[l.slice(0, at)] = l.slice(at + 1);
  }
  return { kind: block[0].slice(5), fields, payload: block.join('\n'), signature: lines[end].slice(SIG.length).trim() };
}

export function verifySigned(parsed, publicKeyPem) {
  if (!parsed?.payload || !parsed.signature) return false;
  try {
    return verify(null, Buffer.from(parsed.payload), createPublicKey(publicKeyPem), Buffer.from(parsed.signature, 'base64'));
  } catch {
    return false;
  }
}

// The desk's agent keys: private halves in keysDir, public halves registered
// in the origin (desk-keys/), where the gate reads them. Made once.
export function ensureKeys(keysDir, originDir) {
  mkdirSync(keysDir, { recursive: true });
  const registry = join(originDir, 'desk-keys');
  mkdirSync(registry, { recursive: true });
  for (const role of ['reviewer', 'shipper']) {
    const priv = join(keysDir, `${role}.pem`);
    if (!existsSync(priv)) {
      const { privateKey } = generateKeyPairSync('ml-dsa-65');
      writeFileSync(priv, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    }
    const pub = createPublicKey(createPrivateKey(readFileSync(priv, 'utf8'))).export({ type: 'spki', format: 'pem' });
    writeFileSync(join(registry, `${role}.pub.pem`), pub);
  }
  return registry;
}

// The registered public keys, or null when the origin has none (then the
// gate keeps its unsigned rules, as in live runs 1 and 2).
export function registeredKeys(originDir) {
  const dir = join(originDir, 'desk-keys');
  const keys = {};
  for (const role of ['reviewer', 'shipper']) {
    const f = join(dir, `${role}.pub.pem`);
    if (existsSync(f)) keys[role] = readFileSync(f, 'utf8');
  }
  return keys.reviewer && keys.shipper ? keys : null;
}

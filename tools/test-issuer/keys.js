// TEST-ONLY RSA-2048 keys for the synthetic test issuer. Anything signed with
// them proves nothing, and no verifier may trust them (SECURITY_NOTES.md).
//
//   generateTestKeys()      in memory only; gone when the process exits
//   loadOrCreateTestKeys()  kept under .keys/ (gitignored) so separate CLI steps
//                           (sign, then verify) share one key on this machine

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEY_BITS = 2048;
// Hardcoded by RSAVerifier65537 in the circuit.
const PUBLIC_EXPONENT = 65537;

const KEY_DIR = path.join(__dirname, '.keys');
const PRIVATE_KEY_PATH = path.join(KEY_DIR, 'test_issuer_private.pem');
const PUBLIC_KEY_PATH = path.join(KEY_DIR, 'test_issuer_public.pem');
const COMPROMISED_KEYS_PATH = path.join(__dirname, '..', '..', 'security', 'compromised-keys.json');

const modulusHex = (publicKey) => Buffer.from(publicKey.export({ format: 'jwk' }).n, 'base64url').toString('hex');

// A key whose private half is public (e.g. the v1 demo key copied back in by hand)
// must not be used even for tests: fixtures made with it could pass as v1 proofs.
function assertNotCompromised(publicKey) {
  const { keys } = JSON.parse(fs.readFileSync(COMPROMISED_KEYS_PATH, 'utf8'));
  const hex = modulusHex(publicKey);
  const hit = keys.find((k) => k.modulus_hex === hex);
  if (hit) throw new Error(`Refusing a known-compromised key: ${hit.label}. Delete ${KEY_DIR} and retry.`);
}

function generateTestKeys() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: KEY_BITS, publicExponent: PUBLIC_EXPONENT });
}

// Refuses to replace existing keys unless force: outputs signed with them would go stale.
function writeTestKeys({ force = false } = {}) {
  const existing = [PRIVATE_KEY_PATH, PUBLIC_KEY_PATH].filter((p) => fs.existsSync(p));
  if (existing.length > 0 && !force) {
    throw new Error(`Test keys already exist in ${KEY_DIR}. Pass --force to replace them.`);
  }
  const { publicKey, privateKey } = generateTestKeys();
  fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey.export({ type: 'spki', format: 'pem' }));
  return { publicKey, privateKey };
}

function loadOrCreateTestKeys() {
  if (!fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PUBLIC_KEY_PATH)) {
    return writeTestKeys({ force: true });
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(PRIVATE_KEY_PATH, 'utf8'));
  const publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'));
  assertNotCompromised(publicKey);
  return { publicKey, privateKey };
}

module.exports = {
  generateTestKeys,
  writeTestKeys,
  loadOrCreateTestKeys,
  assertNotCompromised,
  modulusHex,
  KEY_DIR,
  PUBLIC_KEY_PATH,
  PUBLIC_EXPONENT,
};

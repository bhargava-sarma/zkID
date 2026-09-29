// Compact, URL-safe encoding of an issuer-signed age proof, small enough for a
// QR code. 270 bytes:
//
//   version (1) | proof type (1) | issuer key id (8) | cutoff date (4) | proof (8 x 32)
//
// The issuer's 2048-bit key is not included. A verifier looks it up by key id
// in its own trusted list and checks the proof against that key, so a code
// can't bring its own issuer.

export const CODE_VERSION = 1;
export const CREDENTIAL_AGE_PROOF = 1; // CredentialAgeProof(119), release circuit-v1

const CODE_BYTES = 270;
const LIMB_BITS = 121n;
const LIMB_COUNT = 17;

// Modulus limbs are 17 x 121 bits, least significant first (as in the circuit).
export function limbsToBigInt(limbs) {
  return limbs.reduceRight((acc, limb) => (acc << LIMB_BITS) + BigInt(limb), 0n);
}

export function bigIntToLimbs(value) {
  const mask = (1n << LIMB_BITS) - 1n;
  return Array.from({ length: LIMB_COUNT }, (_, i) => ((value >> (LIMB_BITS * BigInt(i))) & mask).toString());
}

function toBytes(value, length) {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  if (value !== 0n) throw new Error(`Value does not fit in ${length} bytes.`);
  return out;
}

const fromBytes = (bytes) => bytes.reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));

function toBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(text) {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
}

// First 8 bytes of SHA-256 over the big-endian modulus, as hex.
export async function issuerKeyId(modulusLimbs) {
  const modulus = toBytes(limbsToBigInt(modulusLimbs), 256);
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', modulus)).slice(0, 8));
}

// snarkjs affine coordinates in a fixed order: a.x a.y b.x0 b.x1 b.y0 b.y1 c.x c.y
function coordinates({ pi_a: a, pi_b: b, pi_c: c }) {
  if (a[2] !== '1' || c[2] !== '1' || b[2][0] !== '1' || b[2][1] !== '0') {
    throw new Error('Expected a Groth16 proof in affine form.');
  }
  return [a[0], a[1], b[0][0], b[0][1], b[1][0], b[1][1], c[0], c[1]];
}

// publicSignals: 17 modulus limbs, then the cutoff date (YYYYMMDD).
export async function encodeProofCode(proof, publicSignals) {
  if (publicSignals.length !== LIMB_COUNT + 1) {
    throw new Error(`Expected ${LIMB_COUNT + 1} public signals, got ${publicSignals.length}.`);
  }
  const bytes = new Uint8Array(CODE_BYTES);
  bytes[0] = CODE_VERSION;
  bytes[1] = CREDENTIAL_AGE_PROOF;
  bytes.set(fromHex(await issuerKeyId(publicSignals.slice(0, LIMB_COUNT))), 2);
  bytes.set(toBytes(BigInt(publicSignals[LIMB_COUNT]), 4), 10);
  coordinates(proof).forEach((v, i) => bytes.set(toBytes(BigInt(v), 32), 14 + i * 32));
  return toBase64Url(bytes);
}

// Throws unless the code is well formed and of a known version and type.
export function decodeProofCode(code) {
  const bytes = fromBase64Url(code);
  if (bytes.length !== CODE_BYTES) throw new Error(`Expected ${CODE_BYTES} bytes, got ${bytes.length}.`);
  if (bytes[0] !== CODE_VERSION) throw new Error(`Unsupported code version ${bytes[0]}.`);
  if (bytes[1] !== CREDENTIAL_AGE_PROOF) throw new Error(`Unsupported proof type ${bytes[1]}.`);
  const n = (i) => fromBytes(bytes.subarray(14 + i * 32, 46 + i * 32)).toString();
  return {
    keyId: toHex(bytes.subarray(2, 10)),
    thresholdDate: Number(fromBytes(bytes.subarray(10, 14))),
    proof: {
      pi_a: [n(0), n(1), '1'],
      pi_b: [[n(2), n(3)], [n(4), n(5)], ['1', '0']],
      pi_c: [n(6), n(7), '1'],
      protocol: 'groth16',
      curve: 'bn128',
    },
  };
}

// The code inside a scanned verifier link, or a bare code. Null for anything else.
export function codeFromText(text) {
  const trimmed = text.trim();
  const inLink = trimmed.match(/#\/verify\?(?:[^#]*&)?p=([A-Za-z0-9_-]+)/);
  if (inLink) return inLink[1];
  return /^[A-Za-z0-9_-]{360}$/.test(trimmed) ? trimmed : null;
}

// The fragment never reaches a server, so the proof stays in the browser.
export const verifierLink = (code, origin = window.location.origin) => `${origin}/#/verify?p=${code}`;

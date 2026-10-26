// The input of Anon Aadhaar's circuit, AadhaarQRVerifier(121, 17, 1536), built
// from a decoded Secure QR and the RSA modulus that signed it. No platform API:
// the Node package (index.mjs) and the holder app in the browser both use it.
//
// Every failure throws a CircuitError with a code. Nothing falls back silently.

import { poseidon9 } from 'poseidon-lite/poseidon9';
import { toHex } from '../secure-qr/layout.mjs';

export class CircuitError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'CircuitError';
    this.code = code;
  }
}

export const LIMB_BITS = 121;
export const LIMBS = 17;
export const MAX_DATA_BYTES = 1536;
// The photo extractor accepts at most this many bytes from the photo's first
// byte to the end of the SHA-padded data (zk-email SelectSubArray, 10-bit length).
export const MAX_PHOTO_SPAN = 1023;
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Public signals in the order snarkjs returns them: 7 outputs, then 2 public inputs.
export const PUBLIC_SIGNALS = ['pubkeyHash', 'nullifier', 'timestamp', 'ageAbove18', 'gender', 'pinCode', 'state', 'nullifierSeed', 'signalHash'];

export function namedSignals(publicSignals) {
  if (!Array.isArray(publicSignals) || publicSignals.length !== PUBLIC_SIGNALS.length) {
    throw new CircuitError('BAD_PUBLIC_SIGNALS', `Expected ${PUBLIC_SIGNALS.length} public signals.`);
  }
  return Object.fromEntries(PUBLIC_SIGNALS.map((name, i) => [name, String(publicSignals[i])]));
}

const bytesToBigInt = (bytes) => BigInt(`0x${toHex(bytes)}`);

// Least-significant limb first.
function limbs(value) {
  const mask = (1n << BigInt(LIMB_BITS)) - 1n;
  return Array.from({ length: LIMBS }, (_, i) => (value >> (BigInt(LIMB_BITS) * BigInt(i))) & mask);
}

function checkModulus(modulus) {
  if (typeof modulus !== 'bigint' || modulus.toString(2).length !== 2048) {
    throw new CircuitError('UNSUPPORTED_KEY', 'The circuit verifies RSA-2048 with e = 65537 only.');
  }
  return modulus;
}

// The circuit's pubkeyHash output: Poseidon over the 17 key limbs, merged in
// pairs (limb[2i] + limb[2i+1] * 2^121) into 9 inputs.
export function keyHashFromModulus(modulus) {
  const l = limbs(checkModulus(modulus));
  const inputs = [];
  for (let i = 0; i < LIMBS; i += 2) inputs.push(i + 1 < LIMBS ? l[i] + (l[i + 1] << BigInt(LIMB_BITS)) : l[i]);
  return poseidon9(inputs).toString();
}

// SHA-256 padding, then zeros up to MAX_DATA_BYTES (as zk-email's sha256Pad).
function sha256Pad(message) {
  const paddedLength = Math.ceil((message.length + 9) / 64) * 64;
  if (paddedLength > MAX_DATA_BYTES) {
    throw new CircuitError('DATA_TOO_LONG', `${message.length} signed bytes need ${paddedLength} padded bytes; the circuit takes ${MAX_DATA_BYTES}.`);
  }
  const padded = new Uint8Array(MAX_DATA_BYTES);
  padded.set(message);
  padded[message.length] = 0x80;
  new DataView(padded.buffer).setBigUint64(paddedLength - 8, BigInt(message.length * 8));
  return { padded, paddedLength };
}

function fieldElement(name, value) {
  let v;
  try {
    v = BigInt(value);
  } catch {
    throw new CircuitError('BAD_PUBLIC_INPUT', `${name} is not an integer.`);
  }
  if (v < 0n || v >= FIELD) throw new CircuitError('BAD_PUBLIC_INPUT', `${name} is outside the BN254 scalar field.`);
  return v.toString();
}

// `qr` is a decoded Secure QR (decodeSecureQr in secure-qr.mjs or web.mjs);
// `modulus` the signing key's modulus as a BigInt. Only the age bit is revealed:
// gender, PIN code and state stay hidden (docs/THREAT_MODEL.md, A6.1). The
// signature is not checked here; the circuit checks it.
export function circuitInput(qr, modulus, { nullifierSeed, signalHash }) {
  if (qr.version !== 'V2' && qr.version !== 'V5') {
    throw new CircuitError('UNSUPPORTED_LAYOUT', `The circuit reads the V2/V5 field layout; this code is ${qr.version}.`);
  }
  const { padded, paddedLength } = sha256Pad(qr.signedData);
  const span = paddedLength - qr.photo.offset;
  if (span > MAX_PHOTO_SPAN) {
    throw new CircuitError('PHOTO_TOO_LARGE', `The photo and what follows it take ${span} padded bytes; the circuit accepts ${MAX_PHOTO_SPAN}.`);
  }
  return {
    qrDataPadded: Array.from(padded, String),
    qrDataPaddedLength: String(paddedLength),
    delimiterIndices: qr.delimiterIndices.map(String),
    signature: limbs(bytesToBigInt(qr.signature)).map(String),
    pubKey: limbs(checkModulus(modulus)).map(String),
    revealAgeAbove18: '1',
    revealGender: '0',
    revealPinCode: '0',
    revealState: '0',
    nullifierSeed: fieldElement('nullifierSeed', nullifierSeed),
    signalHash: fieldElement('signalHash', signalHash),
  };
}

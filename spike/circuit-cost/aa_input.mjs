// Circuit input for Anon Aadhaar's AadhaarQRVerifier(121, 17, 1536) from a
// Secure QR, built the way its SDK does (packages/core/src/generateArgs.ts at
// commit 4dad918). Used only to measure proving cost; the data is synthetic.

import crypto from 'node:crypto';
import { decodeSecureQr } from '../../packages/secure-qr/secure-qr.mjs';
import { makeSyntheticSecureQr } from '../../packages/secure-qr/synthetic.mjs';

export const MAX_DATA_BYTES = 512 * 3;

// SHA-256 padding, then zeros up to maxBytes (zk-email's sha256Pad).
export function sha256Pad(message, maxBytes) {
  const blocks = Math.ceil((message.length + 9) / 64);
  const padded = Buffer.alloc(maxBytes);
  if (blocks * 64 > maxBytes) throw new Error(`${message.length} bytes need ${blocks * 64} padded bytes; max is ${maxBytes}.`);
  message.copy(padded);
  padded[message.length] = 0x80;
  padded.writeBigUInt64BE(BigInt(message.length * 8), blocks * 64 - 8);
  return { padded, paddedLength: blocks * 64 };
}

// Least-significant limb first, as decimal strings.
export function limbs(value, bits = 121, count = 17) {
  const mask = (1n << BigInt(bits)) - 1n;
  return Array.from({ length: count }, (_, i) => ((value >> (BigInt(bits) * BigInt(i))) & mask).toString());
}

const toBigInt = (buf) => BigInt(`0x${Buffer.from(buf).toString('hex')}`);

export function anonAadhaarInput(qrText, publicKey, { nullifierSeed = 1234567890n, signalHash = 1n } = {}) {
  const qr = decodeSecureQr(qrText);
  const { padded, paddedLength } = sha256Pad(qr.signedData, MAX_DATA_BYTES);
  const delimiterIndices = [];
  for (let i = 0; i < padded.length && delimiterIndices.length < 18; i++) if (padded[i] === 0xff) delimiterIndices.push(i);
  const modulus = toBigInt(Buffer.from(publicKey.export({ format: 'jwk' }).n, 'base64url'));
  return {
    qrDataPadded: Array.from(padded, String),
    qrDataPaddedLength: String(paddedLength),
    delimiterIndices: delimiterIndices.map(String),
    signature: limbs(toBigInt(qr.signature)),
    pubKey: limbs(modulus),
    revealAgeAbove18: '1',
    revealGender: '0',
    revealPinCode: '0',
    revealState: '0',
    nullifierSeed: nullifierSeed.toString(),
    signalHash: signalHash.toString(),
  };
}

// A fresh synthetic V2 QR under an ephemeral key, and its circuit input.
export function syntheticInput(options = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const { text } = makeSyntheticSecureQr(privateKey, options);
  return { input: anonAadhaarInput(text, publicKey), signedBytes: decodeSecureQr(text).signedData.length };
}

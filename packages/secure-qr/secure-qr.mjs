// Aadhaar Secure QR in Node: decode, parse and verify, with Node's zlib and
// crypto. The layout rules are in layout.mjs; web.mjs is the browser version.
//
// Every failure throws a SecureQrError with a code. Nothing falls back silently.

import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { SecureQrError, compressionOf, parseSignedData, qrTextToBytes, splitSignature } from './layout.mjs';

export {
  FIELDS,
  SecureQrError,
  bytesToQrText,
  parseReferenceId,
  parseSignedData,
  qrTextToBytes,
  splitSignature,
} from './layout.mjs';

export function decompress(bytes) {
  const compression = compressionOf(bytes);
  try {
    return { data: compression === 'gzip' ? zlib.gunzipSync(bytes) : zlib.inflateSync(bytes), compression };
  } catch (err) {
    throw new SecureQrError('CORRUPT_COMPRESSION', err.message);
  }
}

const toKey = (key) => (key instanceof crypto.X509Certificate ? key.publicKey : key);

export function verifySignature(signedData, signature, key) {
  return crypto.verify('sha256', signedData, { key: toKey(key), padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
}

// The layout-independent part: text -> bytes -> decompress -> data and signature.
// The signature can be checked even when the field layout is unknown.
export function decodeEnvelope(text) {
  const compressed = Buffer.from(qrTextToBytes(text));
  const { data, compression } = decompress(compressed);
  return { compression, compressedLength: compressed.length, dataLength: data.length, ...splitSignature(data) };
}

export function decodeSecureQr(text) {
  const envelope = decodeEnvelope(text);
  return { ...envelope, ...parseSignedData(envelope.signedData) };
}

// certs: [{ label, cert: X509Certificate }]. Returns the entry that verifies, or null.
export function findSigner(decoded, certs) {
  return certs.find(({ cert }) => verifySignature(decoded.signedData, decoded.signature, cert)) ?? null;
}

// Aadhaar Secure QR with Web APIs only (DecompressionStream, WebCrypto), for
// the holder app: the same layout rules as layout.mjs, asynchronous. Node 22
// has these APIs too, so the tests run it there.
//
// Every failure throws a SecureQrError with a code. Nothing falls back silently.

import { SecureQrError, compressionOf, fromHex, parseSignedData, qrTextToBytes, splitSignature } from './layout.mjs';

export { FIELDS, SecureQrError, parseReferenceId, parseSignedData, toHex } from './layout.mjs';

async function inflate(bytes, format) {
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch (err) {
    throw new SecureQrError('CORRUPT_COMPRESSION', String(err?.message ?? err));
  }
}

export async function decodeEnvelope(text) {
  const compressed = qrTextToBytes(text);
  const compression = compressionOf(compressed);
  const data = await inflate(compressed, compression === 'gzip' ? 'gzip' : 'deflate');
  return { compression, compressedLength: compressed.length, dataLength: data.length, ...splitSignature(data) };
}

export async function decodeSecureQr(text) {
  const envelope = await decodeEnvelope(text);
  return { ...envelope, ...parseSignedData(envelope.signedData) };
}

const base64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// An RSA public key with e = 65537, from its modulus in hex, for verifying.
export function importRsaKey(modulusHex) {
  return crypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: base64url(fromHex(modulusHex)), e: 'AQAB', alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
}

export const verifySignature = (signedData, signature, cryptoKey) =>
  crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, signedData);

// keys: [{ ..., cryptoKey }]. Returns the first entry whose key verifies, or null.
export async function findSigner(decoded, keys) {
  for (const key of keys) {
    if (await verifySignature(decoded.signedData, decoded.signature, key.cryptoKey)) return key;
  }
  return null;
}

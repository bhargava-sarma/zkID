// Aadhaar Secure QR layout: the decoding steps that need no platform API, on
// Uint8Array (a Node Buffer is one). secure-qr.mjs adds Node's zlib and crypto;
// web.mjs adds a browser's DecompressionStream and WebCrypto. See
// docs/issuer-research.md for the sources behind every layout rule here.
//
//   QR text    a decimal integer
//   -> bytes   big-endian
//   -> data    gzip (UIDAI's codes) or zlib (Anon Aadhaar's test data)
//   data       = signedData || signature (last 256 bytes)
//   signature  RSASSA-PKCS1-v1_5 over SHA-256(signedData), RSA-2048
//   signedData V2, V5: "V2"/"V5" 0xFF then 17 text fields, each ended by 0xFF,
//                  then the photo (V5: then 27 more bytes, purpose unknown)
//              V1: 16 text fields, each ended by 0xFF, then the photo, then
//                  SHA-256 hashes of mobile and/or email (32 bytes each)
//   photo      a JPEG 2000 codestream: starts FF 4F, ends FF D9
//
// Every failure throws a SecureQrError with a code. Nothing falls back silently.

export class SecureQrError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'SecureQrError';
    this.code = code;
  }
}

const DELIMITER = 0xff;
export const SIGNATURE_BYTES = 256;
const JPEG2000_SOC = [0xff, 0x4f];
const JPEG2000_EOC = [0xff, 0xd9];

// Field order: UIDAI's V1 user manual, and Anon Aadhaar's notes on V2
// (packages/circuits/src/helpers/extractor.circom at commit 4dad918). V5 as
// measured on one real code (docs/issuer-research.md, section 3.2).
const V1_FIELDS = [
  'emailMobileIndicator',
  'referenceId',
  'name',
  'dob',
  'gender',
  'careOf',
  'district',
  'landmark',
  'house',
  'location',
  'pincode',
  'postOffice',
  'state',
  'street',
  'subDistrict',
  'vtc',
];
const V2_FIELDS = [...V1_FIELDS, 'mobileLast4'];
// Field 17 held 10 letters and digits in the one V5 code inspected, likely a
// masked mobile number (not confirmed).
const V5_FIELDS = [...V1_FIELDS, 'mobile'];
export const FIELDS = { V1: V1_FIELDS, V2: V2_FIELDS, V5: V5_FIELDS };

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
export const toHex = (bytes) => Array.from(bytes, (b) => HEX[b]).join('');
export function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}
const latin1 = (bytes) => String.fromCharCode(...bytes);

export function qrTextToBytes(text) {
  const digits = String(text).trim();
  if (!/^[0-9]+$/.test(digits)) throw new SecureQrError('NOT_DECIMAL', 'QR text must be a decimal integer.');
  let hex = BigInt(digits).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return fromHex(hex);
}

export const bytesToQrText = (bytes) => BigInt(`0x${toHex(bytes)}`).toString(10);

// zlib's header: CMF 0x78, and (CMF * 256 + FLG) divisible by 31.
const isZlib = (b) => b.length > 1 && b[0] === 0x78 && ((b[0] << 8) | b[1]) % 31 === 0;

// 'gzip' or 'zlib', from the first two bytes.
export function compressionOf(bytes) {
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return 'gzip';
  if (isZlib(bytes)) return 'zlib';
  throw new SecureQrError('UNSUPPORTED_COMPRESSION', `Header ${toHex(bytes.subarray(0, 2))} is neither gzip nor zlib.`);
}

export function splitSignature(data) {
  if (data.length <= SIGNATURE_BYTES) {
    throw new SecureQrError('TOO_SHORT', `${data.length} bytes cannot hold data and a ${SIGNATURE_BYTES}-byte signature.`);
  }
  return {
    signedData: data.subarray(0, data.length - SIGNATURE_BYTES),
    signature: data.subarray(data.length - SIGNATURE_BYTES),
  };
}

// The version marker is the ASCII text before the first delimiter, if it looks
// like "V<digits>". V1 has no marker: its first field is the 1-digit indicator.
function readVersion(signedData) {
  const first = signedData.indexOf(DELIMITER);
  if (first === -1) throw new SecureQrError('MALFORMED', 'No field delimiter (0xFF) found.');
  const head = latin1(signedData.subarray(0, first));
  if (/^V[0-9]+$/.test(head)) return { version: head, start: first + 1 };
  return { version: 'V1', start: 0 };
}

function lastIndexOfPair(bytes, [a, b]) {
  for (let i = bytes.length - 2; i >= 0; i--) if (bytes[i] === a && bytes[i + 1] === b) return i;
  return -1;
}

export function parseSignedData(signedData) {
  const { version, start } = readVersion(signedData);
  const names = FIELDS[version];
  if (!names) throw new SecureQrError('UNSUPPORTED_VERSION', `Format ${version} is not supported.`);

  const fields = {};
  const delimiterIndices = start > 0 ? [start - 1] : [];
  let pos = start;
  for (const name of names) {
    const end = signedData.indexOf(DELIMITER, pos);
    if (end === -1) throw new SecureQrError('MALFORMED', `No delimiter after field "${name}".`);
    fields[name] = signedData.subarray(pos, end);
    delimiterIndices.push(end);
    pos = end + 1;
  }

  if (signedData[pos] !== JPEG2000_SOC[0] || signedData[pos + 1] !== JPEG2000_SOC[1]) {
    throw new SecureQrError('PHOTO_NOT_JPEG2000', `No JPEG 2000 start marker at byte ${pos}.`);
  }
  const eoc = lastIndexOfPair(signedData, JPEG2000_EOC);
  if (eoc < pos) throw new SecureQrError('PHOTO_NOT_JPEG2000', 'No JPEG 2000 end marker after the photo start.');
  const photo = { offset: pos, length: eoc + 2 - pos };

  return {
    version,
    fields,
    delimiterIndices,
    photo,
    // V1: the mobile/email hashes. V2 is described as having none; V5 had 27
    // bytes in the one code inspected. Reported, not assumed.
    trailingBytes: signedData.length - (photo.offset + photo.length),
  };
}

// Last 4 digits of the Aadhaar number, then the generation time in IST as
// YYYYMMDDHHMMSSsss (21 digits in total).
export function parseReferenceId(referenceId) {
  const text = typeof referenceId === 'string' ? referenceId : latin1(referenceId);
  const m = /^([0-9]{4})([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{3})$/.exec(text);
  if (!m) throw new SecureQrError('MALFORMED_REFERENCE_ID', `Expected 21 digits, got ${text.length} characters.`);
  const [, last4, y, mo, d, h, mi, s, ms] = m;
  const generatedAt = new Date(`${y}-${mo}-${d}T${h}:${mi}:${s}.${ms}+05:30`);
  if (Number.isNaN(generatedAt.getTime())) throw new SecureQrError('MALFORMED_REFERENCE_ID', 'Timestamp is not a valid date.');
  return { aadhaarLast4: last4, generatedAt };
}

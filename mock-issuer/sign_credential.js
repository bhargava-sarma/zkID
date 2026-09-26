#!/usr/bin/env node
// Signs payload.json with the mock issuer key.
// Writes signed_credential.json and circuit_inputs.json. Also used by the backend.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REQUIRED_FIELDS = ['dob', 'gender', 'id_number', 'name'];

// Largest width that keeps SHA-256 at two blocks: 119*8 + 1 + 64 <= 1024.
const PAYLOAD_FIXED_BYTES = 119;
const PAD_CHAR = ' ';

// RSA-2048 as 17 x 121-bit limbs, matching zk-email's RSAVerifier65537(121, 17).
const LIMB_BITS = 121;
const LIMB_COUNT = 17;

const PAYLOAD_PATH = path.join(__dirname, 'payload.json');
const PRIVATE_KEY_PATH = path.join(__dirname, 'mock_issuer_private.pem');
const PUBLIC_KEY_PATH = path.join(__dirname, 'mock_issuer_public.pem');
const CREDENTIAL_PATH = path.join(__dirname, 'signed_credential.json');
const CIRCUIT_INPUTS_PATH = path.join(__dirname, 'circuit_inputs.json');

// Gregorian calendar, including leap years.
function isCalendarDate(year, month, day) {
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= daysInMonth[month - 1];
}

// The circuit hashes raw bytes, so reject anything JSON would escape or encode as multi-byte.
function validatePayload(payload) {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('payload.json must contain a JSON object.');
  }

  const keys = Object.keys(payload).sort();
  const expected = [...REQUIRED_FIELDS].sort();
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    throw new Error(
      `payload.json must contain exactly these keys: ${expected.join(', ')}. ` +
        `Found: ${keys.join(', ') || '(none)'}.`
    );
  }

  for (const key of keys) {
    const value = payload[key];
    if (typeof value !== 'string') {
      throw new Error(`Field "${key}" must be a string, got ${typeof value}.`);
    }
    if (value.length === 0) {
      throw new Error(`Field "${key}" must not be empty.`);
    }
    if (!/^[\x20-\x7E]+$/.test(value)) {
      throw new Error(
        `Field "${key}" contains a non-printable or non-ASCII character. ` +
          'Only printable ASCII (0x20-0x7E) is allowed.'
      );
    }
    if (value.includes('"') || value.includes('\\')) {
      throw new Error(`Field "${key}" contains a quote or backslash, which JSON escaping would expand.`);
    }
  }

  if (!/^\d{4}-\d{2}-\d{2}$/.test(payload.dob)) {
    throw new Error(`Field "dob" must be YYYY-MM-DD, got "${payload.dob}".`);
  }
  const [year, month, day] = payload.dob.split('-').map(Number);
  if (!isCalendarDate(year, month, day)) {
    throw new Error(`Field "dob" is not a real calendar date: "${payload.dob}".`);
  }
  if (!/^\d{12}$/.test(payload.id_number)) {
    throw new Error(`Field "id_number" must be exactly 12 digits.`);
  }
  if (!['M', 'F', 'O'].includes(payload.gender)) {
    throw new Error(`Field "gender" must be one of M, F, O. Got "${payload.gender}".`);
  }
}

// Canonical form: keys sorted, no whitespace.
function serializePayload(payload) {
  const ordered = {};
  for (const key of Object.keys(payload).sort()) {
    ordered[key] = payload[key];
  }
  return JSON.stringify(ordered);
}

// Trailing spaces: still valid JSON, and can't form a second `"dob":"`.
function padToFixedLength(serialized) {
  const length = Buffer.byteLength(serialized, 'utf8');
  if (length > PAYLOAD_FIXED_BYTES) {
    throw new Error(
      `Canonical payload is ${length} bytes, over the ${PAYLOAD_FIXED_BYTES}-byte fixed width.`
    );
  }
  return serialized + PAD_CHAR.repeat(PAYLOAD_FIXED_BYTES - length);
}

function bufferToBigInt(buf) {
  return buf.length === 0 ? 0n : BigInt('0x' + buf.toString('hex'));
}

// Least-significant limb first, as decimal strings (limbs exceed Number.MAX_SAFE_INTEGER).
function toLimbs(value, limbBits, limbCount) {
  const mask = (1n << BigInt(limbBits)) - 1n;
  const limbs = [];
  let remaining = value;
  for (let i = 0; i < limbCount; i++) {
    limbs.push((remaining & mask).toString());
    remaining >>= BigInt(limbBits);
  }
  if (remaining !== 0n) {
    throw new Error(`Value does not fit in ${limbCount} limbs of ${limbBits} bits.`);
  }
  return limbs;
}

// RSASSA-PKCS1-v1_5 over SHA-256. crypto.sign hashes the bytes itself.
function signBytes(bytes, privateKey) {
  return crypto.sign('sha256', bytes, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });
}

function buildCircuitInputs(canonical, serializedBytes, signature, publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  const modulusBytes = Buffer.from(jwk.n, 'base64url');
  const exponent = Number(bufferToBigInt(Buffer.from(jwk.e, 'base64url')));
  if (exponent !== 65537) {
    throw new Error(`Public exponent is ${exponent}; the circuit requires 65537.`);
  }

  const canonicalLength = Buffer.byteLength(canonical, 'utf8');
  return {
    algorithm: {
      signature_scheme: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
      modulus_bits: modulusBytes.length * 8,
      exponent,
    },
    limb_layout: {
      limb_bits: LIMB_BITS,
      limb_count: LIMB_COUNT,
      order: 'least-significant-limb-first',
      encoding: 'decimal string',
    },
    payload_byte_length: serializedBytes.length,
    payload_bit_length: serializedBytes.length * 8,
    sha256_block_count: Math.ceil((serializedBytes.length * 8 + 1 + 64) / 512),
    padding: {
      scheme: 'trailing 0x20 after the closing brace, covered by the signature',
      canonical_byte_length: canonicalLength,
      pad_byte_count: PAYLOAD_FIXED_BYTES - canonicalLength,
    },
    modulus_hex: modulusBytes.toString('hex'),
    exponent,
    modulus_limbs: toLimbs(bufferToBigInt(modulusBytes), LIMB_BITS, LIMB_COUNT),
    signature_limbs: toLimbs(bufferToBigInt(signature), LIMB_BITS, LIMB_COUNT),
    message_bytes: Array.from(serializedBytes),
  };
}

// Temp file + rename, so a reader never sees a half-written file.
function writeAtomic(filePath, contents) {
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, contents);
  fs.renameSync(tmpPath, filePath);
}

function main() {
  for (const [label, filePath] of [
    ['payload.json', PAYLOAD_PATH],
    ['mock_issuer_private.pem', PRIVATE_KEY_PATH],
    ['mock_issuer_public.pem', PUBLIC_KEY_PATH],
  ]) {
    if (!fs.existsSync(filePath)) {
      console.error(`[SIGN] Missing ${label}. Run: node generate_keypair.js`);
      process.exit(1);
    }
  }

  const payload = JSON.parse(fs.readFileSync(PAYLOAD_PATH, 'utf8'));
  validatePayload(payload);
  console.log('[SIGN] Payload validated: 4 fields, printable ASCII, no escape sequences');

  const canonical = serializePayload(payload);
  const serialized = padToFixedLength(canonical);
  const serializedBytes = Buffer.from(serialized, 'utf8');
  const canonicalLength = Buffer.byteLength(canonical, 'utf8');
  console.log(`[SIGN] Canonical: ${canonicalLength} bytes`);
  console.log(`[SIGN] ${canonical}`);
  console.log(
    `[SIGN] Padded:    ${serializedBytes.length} bytes / ${serializedBytes.length * 8} bits ` +
      `(+${PAYLOAD_FIXED_BYTES - canonicalLength} x 0x20)`
  );

  const sha256Hex = crypto.createHash('sha256').update(serializedBytes).digest('hex');
  console.log(`[SIGN] SHA-256: ${sha256Hex}`);

  const privateKey = crypto.createPrivateKey(fs.readFileSync(PRIVATE_KEY_PATH, 'utf8'));
  const publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'));
  const signature = signBytes(serializedBytes, privateKey);
  const signatureHex = signature.toString('hex');
  console.log(`[SIGN] Signature: ${signature.length} bytes (${signatureHex.substring(0, 32)}...)`);

  // Build both documents before writing either, so they can't diverge.
  const credential = { payload, serialized, sha256: sha256Hex, signature: signatureHex };
  const circuitInputs = buildCircuitInputs(canonical, serializedBytes, signature, publicKey);

  writeAtomic(CREDENTIAL_PATH, JSON.stringify(credential, null, 2) + '\n');
  console.log(`[SIGN] Wrote ${path.basename(CREDENTIAL_PATH)}`);
  writeAtomic(CIRCUIT_INPUTS_PATH, JSON.stringify(circuitInputs, null, 2) + '\n');
  console.log(`[SIGN] Wrote ${path.basename(CIRCUIT_INPUTS_PATH)}`);

  console.log(
    `[SIGN] Circuit sizing: ${circuitInputs.payload_bit_length} message bits, ` +
      `${circuitInputs.sha256_block_count} SHA-256 block(s)`
  );
  console.log('[SIGN] Next: node verify_credential.js');
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(`[SIGN] ERROR: ${err.message}`);
    process.exit(1);
  }
}

module.exports = {
  isCalendarDate,
  validatePayload,
  serializePayload,
  padToFixedLength,
  signBytes,
  buildCircuitInputs,
  PAYLOAD_FIXED_BYTES,
};

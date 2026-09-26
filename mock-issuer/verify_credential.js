#!/usr/bin/env node
// Independently verifies signed_credential.json and circuit_inputs.json.
// Imports nothing from sign_credential.js on purpose: a format drift in the
// signer must show up here, not be hidden by shared code.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const CREDENTIAL_PATH = path.join(__dirname, 'signed_credential.json');
const PUBLIC_KEY_PATH = path.join(__dirname, 'mock_issuer_public.pem');
const CIRCUIT_INPUTS_PATH = path.join(__dirname, 'circuit_inputs.json');

const REQUIRED_FIELDS = ['dob', 'gender', 'id_number', 'name'];

// Hardcoded, not read from the files under test.
const EXPECTED_LIMB_BITS = 121;
const EXPECTED_LIMB_COUNT = 17;
const PAYLOAD_FIXED_BYTES = 119;
const PAD_CHAR = ' ';
const EXPECTED_SHA256_BLOCKS = 2;

function canonicalSerialize(payload) {
  const ordered = {};
  for (const key of Object.keys(payload).sort()) {
    ordered[key] = payload[key];
  }
  const canonical = JSON.stringify(ordered);
  const length = Buffer.byteLength(canonical, 'utf8');
  if (length > PAYLOAD_FIXED_BYTES) {
    throw new Error(`Canonical payload is ${length} bytes, over the ${PAYLOAD_FIXED_BYTES}-byte width.`);
  }
  return canonical + PAD_CHAR.repeat(PAYLOAD_FIXED_BYTES - length);
}

// Inverse of toLimbs: limbs are least-significant first.
function fromLimbs(limbs, limbBits) {
  const shift = BigInt(limbBits);
  let value = 0n;
  for (let i = limbs.length - 1; i >= 0; i--) {
    value = (value << shift) + BigInt(limbs[i]);
  }
  return value;
}

let failures = 0;
let passes = 0;
let skipped = 0;

function skip(label, reason) {
  console.log(`[VERIFY] SKIP  ${label}`);
  console.log(`[VERIFY]       ${reason}`);
  skipped++;
}

function check(passed, label, detail) {
  console.log(`[VERIFY] ${passed ? 'PASS' : 'FAIL'}  ${label}`);
  if (detail) console.log(`[VERIFY]       ${detail}`);
  if (passed) passes++;
  else failures++;
  return passed;
}

function hexDump(buf) {
  const lines = [];
  for (let offset = 0; offset < buf.length; offset += 16) {
    const slice = buf.subarray(offset, offset + 16);
    const hex = slice.toString('hex').match(/../g).join(' ').padEnd(47, ' ');
    const ascii = Array.from(slice)
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push(`  ${offset.toString(16).padStart(4, '0')}  ${hex}  |${ascii}|`);
  }
  return lines.join('\n');
}

function rsaVerify(message, publicKey, signature) {
  return crypto.verify(
    'sha256',
    message,
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    signature
  );
}

function main() {
  for (const [label, filePath] of [
    ['signed_credential.json', CREDENTIAL_PATH],
    ['mock_issuer_public.pem', PUBLIC_KEY_PATH],
  ]) {
    if (!fs.existsSync(filePath)) {
      console.error(`[VERIFY] Missing ${label}. Run: node generate_keypair.js && node sign_credential.js`);
      process.exit(1);
    }
  }

  const credential = JSON.parse(fs.readFileSync(CREDENTIAL_PATH, 'utf8'));
  const publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'));

  console.log('='.repeat(72));
  console.log('MOCK ISSUER CREDENTIAL - INDEPENDENT VERIFICATION');
  console.log('='.repeat(72));
  console.log(`Credential: ${CREDENTIAL_PATH}`);
  console.log(`Public key: ${PUBLIC_KEY_PATH}`);
  console.log('');

  const structureOk =
    credential.payload &&
    typeof credential.serialized === 'string' &&
    typeof credential.sha256 === 'string' &&
    typeof credential.signature === 'string' &&
    REQUIRED_FIELDS.every((f) => typeof credential.payload[f] === 'string') &&
    Object.keys(credential.payload).length === REQUIRED_FIELDS.length;
  check(structureOk, 'Credential structure: payload(4 string fields), serialized, sha256, signature');
  if (!structureOk) {
    console.error('[VERIFY] Structure is malformed; remaining checks would be meaningless.');
    process.exit(1);
  }

  console.log('');
  console.log('PAYLOAD');
  console.log('-'.repeat(72));
  for (const key of Object.keys(credential.payload).sort()) {
    console.log(`  ${key.padEnd(12)} ${credential.payload[key]}`);
  }

  const reserialized = canonicalSerialize(credential.payload);
  const reserializedBytes = Buffer.from(reserialized, 'utf8');
  const storedBytes = Buffer.from(credential.serialized, 'utf8');

  console.log('');
  console.log('SERIALIZED BYTE STRING (this is what was hashed)');
  console.log('-'.repeat(72));
  console.log(reserialized);
  console.log('');
  console.log(`Byte length: ${reserializedBytes.length} bytes (${reserializedBytes.length * 8} bits)`);
  console.log('');
  console.log('HEX DUMP');
  console.log('-'.repeat(72));
  console.log(hexDump(reserializedBytes));
  console.log('');
  console.log('CHECKS');
  console.log('-'.repeat(72));

  check(
    Buffer.compare(reserializedBytes, storedBytes) === 0,
    'Re-serialized payload matches the stored `serialized` field byte for byte',
    `${reserializedBytes.length} bytes re-derived, ${storedBytes.length} bytes stored`
  );

  const recomputedHash = crypto.createHash('sha256').update(reserializedBytes).digest('hex');
  check(
    recomputedHash === credential.sha256,
    'Recomputed SHA-256 matches the stored hash',
    `recomputed ${recomputedHash}`
  );

  const signatureBytes = Buffer.from(credential.signature, 'hex');
  check(
    rsaVerify(reserializedBytes, publicKey, signatureBytes),
    'RSASSA-PKCS1-v1_5 signature verifies against mock_issuer_public.pem',
    `${signatureBytes.length}-byte signature, ${publicKey.asymmetricKeyDetails.modulusLength}-bit key, ` +
      `e=${publicKey.asymmetricKeyDetails.publicExponent}`
  );

  // Negative controls: a verifier that accepts everything would pass the checks above.
  const tamperedMessage = Buffer.from(reserializedBytes);
  const flipIndex = Math.floor(tamperedMessage.length / 2);
  tamperedMessage[flipIndex] ^= 0x01;
  check(
    !rsaVerify(tamperedMessage, publicKey, signatureBytes),
    'Negative control: message with one flipped bit is REJECTED',
    `flipped low bit of byte ${flipIndex}`
  );

  const tamperedSignature = Buffer.from(signatureBytes);
  tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
  check(
    !rsaVerify(reserializedBytes, publicKey, tamperedSignature),
    'Negative control: signature with one flipped bit is REJECTED',
    'flipped low bit of the final signature byte'
  );

  console.log('');
  console.log('CIRCUIT INPUT CHECKS (circuit_inputs.json)');
  console.log('-'.repeat(72));

  if (!fs.existsSync(CIRCUIT_INPUTS_PATH)) {
    skip(
      'Limb decomposition checks',
      'circuit_inputs.json not found - run sign_credential.js to generate it'
    );
  } else {
    const ci = JSON.parse(fs.readFileSync(CIRCUIT_INPUTS_PATH, 'utf8'));
    const layout = ci.limb_layout || {};

    const geometryOk =
      layout.limb_bits === EXPECTED_LIMB_BITS &&
      layout.limb_count === EXPECTED_LIMB_COUNT &&
      Array.isArray(ci.modulus_limbs) &&
      Array.isArray(ci.signature_limbs) &&
      ci.modulus_limbs.length === EXPECTED_LIMB_COUNT &&
      ci.signature_limbs.length === EXPECTED_LIMB_COUNT;
    check(
      geometryOk,
      `Limb geometry is ${EXPECTED_LIMB_COUNT} x ${EXPECTED_LIMB_BITS}-bit, matching RSAVerifier65537(121, 17)`,
      `declared ${layout.limb_count} x ${layout.limb_bits}-bit; ` +
        `modulus_limbs=${ci.modulus_limbs?.length}, signature_limbs=${ci.signature_limbs?.length}; ` +
        `capacity ${EXPECTED_LIMB_COUNT * EXPECTED_LIMB_BITS} bits >= 2048`
    );

    // An oversized limb still recombines here but fails the circuit's Num2Bits check.
    const limit = 1n << BigInt(EXPECTED_LIMB_BITS);
    const allLimbs = [...(ci.modulus_limbs || []), ...(ci.signature_limbs || [])];
    const oversized = allLimbs.filter((l) => BigInt(l) >= limit).length;
    check(
      allLimbs.length > 0 && oversized === 0,
      `Every limb is < 2^${EXPECTED_LIMB_BITS} (in range for the circuit's Num2Bits check)`,
      `${allLimbs.length} limbs checked, ${oversized} out of range`
    );

    // Compared against the PEM, not modulus_hex in the same file.
    const jwk = publicKey.export({ format: 'jwk' });
    const modulusFromPem = BigInt('0x' + Buffer.from(jwk.n, 'base64url').toString('hex'));
    const modulusFromLimbs = fromLimbs(ci.modulus_limbs || [], EXPECTED_LIMB_BITS);
    check(
      modulusFromLimbs === modulusFromPem,
      'Modulus limbs recombine to the modulus in mock_issuer_public.pem',
      `${modulusFromPem.toString(16).length * 4}-bit modulus, reconstructed from ${EXPECTED_LIMB_COUNT} limbs`
    );

    const signatureFromLimbs = fromLimbs(ci.signature_limbs || [], EXPECTED_LIMB_BITS);
    check(
      signatureFromLimbs === BigInt('0x' + credential.signature),
      'Signature limbs recombine to the signature in signed_credential.json',
      `${signatureBytes.length * 8}-bit signature, reconstructed from ${EXPECTED_LIMB_COUNT} limbs`
    );

    const messageBytes = Buffer.from(ci.message_bytes || []);
    const lengthsOk =
      ci.payload_byte_length === reserializedBytes.length &&
      ci.payload_bit_length === reserializedBytes.length * 8;
    check(
      Buffer.compare(messageBytes, reserializedBytes) === 0 && lengthsOk,
      'message_bytes and declared lengths match the serialized payload',
      `${messageBytes.length} bytes, declared ${ci.payload_byte_length} bytes / ` +
        `${ci.payload_bit_length} bits, ${ci.sha256_block_count} SHA-256 block(s)`
    );

    // Padding is signed, so it is verified too.
    const canonicalLength = ci.padding?.canonical_byte_length;
    const tail = reserializedBytes.subarray(canonicalLength);
    const tailAllSpaces = tail.every((b) => b === 0x20);
    let roundTrips = false;
    try {
      const head = reserializedBytes.subarray(0, canonicalLength).toString('utf8');
      roundTrips = JSON.stringify(JSON.parse(head)) === head;
    } catch (e) {
      roundTrips = false;
    }
    check(
      reserializedBytes.length === PAYLOAD_FIXED_BYTES &&
        tailAllSpaces &&
        roundTrips &&
        ci.sha256_block_count === EXPECTED_SHA256_BLOCKS &&
        canonicalLength + tail.length === PAYLOAD_FIXED_BYTES,
      `Padding is well-formed: ${PAYLOAD_FIXED_BYTES} bytes fixed, tail all 0x20, JSON prefix intact`,
      `${canonicalLength} canonical + ${tail.length} pad = ${reserializedBytes.length}; ` +
        `tail all spaces: ${tailAllSpaces}; prefix round-trips as JSON: ${roundTrips}; ` +
        `${ci.sha256_block_count} SHA-256 block(s)`
    );
  }

  console.log('');
  console.log('='.repeat(72));
  if (failures === 0) {
    console.log(
      `RESULT: SIGNATURE VALID - all ${passes} checks passed` +
        (skipped > 0 ? ` (${skipped} skipped)` : '')
    );
    console.log('='.repeat(72));
    process.exit(0);
  }
  console.log(`RESULT: FAILED - ${failures} check(s) did not pass`);
  console.log('='.repeat(72));
  process.exit(1);
}

try {
  main();
} catch (err) {
  console.error(`[VERIFY] ERROR: ${err.message}`);
  process.exit(1);
}

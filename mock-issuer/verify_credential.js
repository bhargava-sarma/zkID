#!/usr/bin/env node
/**
 * Independent verification of signed_credential.json.
 *
 * This script is deliberately standalone. It reads ONLY signed_credential.json,
 * mock_issuer_public.pem, and (when present) circuit_inputs.json - never the
 * private key, never payload.json, and it imports nothing from
 * sign_credential.js. It also re-implements the canonical serializer inline
 * rather than sharing a helper, so that a mismatch between the documented format
 * and the signing implementation would surface here instead of being hidden by
 * shared code. The duplication is the point.
 *
 * The credential checks (1-6) need only the credential and the public key, so
 * they still run for anyone holding just those two files. The limb checks (7-11)
 * additionally validate circuit_inputs.json and are reported as SKIPPED, not
 * passed, when that file is absent.
 *
 * Usage:
 *   node verify_credential.js
 *
 * Exits 0 only if every check that ran passed.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const CREDENTIAL_PATH = path.join(__dirname, 'signed_credential.json');
const PUBLIC_KEY_PATH = path.join(__dirname, 'mock_issuer_public.pem');
const CIRCUIT_INPUTS_PATH = path.join(__dirname, 'circuit_inputs.json');

const REQUIRED_FIELDS = ['dob', 'gender', 'id_number', 'name'];

// Expected limb geometry, matching RSAVerifier65537(121, 17) from
// @zk-email/circuits. Hardcoded here on purpose: circuit_inputs.json declares its
// own layout, and this script's job is to catch that declaration drifting from
// what the circuit actually takes, so it must not read the expectation from the
// file it is checking.
const EXPECTED_LIMB_BITS = 121;
const EXPECTED_LIMB_COUNT = 17;

// Fixed signed-payload width the circuit is built for. Hardcoded here for the
// same reason as the limb geometry: this script must catch the signer drifting
// from the circuit's expectations, so it cannot read the expectation from the
// files it is checking.
const PAYLOAD_FIXED_BYTES = 119;
const PAD_CHAR = ' '; // 0x20
const EXPECTED_SHA256_BLOCKS = 2;

// =============================================================================
// Independent re-implementation of the canonical serialization
// =============================================================================

/**
 * Rebuilds the signed byte string from a payload object, per the format
 * documented in README.md: keys sorted ascending, JSON.stringify with no space
 * argument, UTF-8 encoded, then padded with trailing 0x20 to a fixed 119 bytes.
 *
 * Independently reimplemented rather than imported, so that a divergence between
 * the documented format and sign_credential.js surfaces as a failure here.
 *
 * @param {object} payload The payload object read from signed_credential.json
 * @returns {string} The padded, signed serialization
 */
function canonicalSerialize(payload) {
  const sortedKeys = Object.keys(payload).sort();
  const ordered = {};
  for (const key of sortedKeys) {
    ordered[key] = payload[key];
  }
  const canonical = JSON.stringify(ordered);
  const length = Buffer.byteLength(canonical, 'utf8');
  if (length > PAYLOAD_FIXED_BYTES) {
    throw new Error(`Canonical payload is ${length} bytes, over the ${PAYLOAD_FIXED_BYTES}-byte width.`);
  }
  return canonical + PAD_CHAR.repeat(PAYLOAD_FIXED_BYTES - length);
}

/**
 * Recombines a limb array back into the BigInt it was split from.
 *
 * Inverse of sign_credential.js's toLimbs, implemented independently: limbs are
 * least-significant-first, so this folds from the top down, shifting left by
 * limbBits per step. Matches zk-email's bigIntToChunkedBytes ordering.
 *
 * @param {string[]} limbs Decimal-string limbs, least significant first
 * @param {number} limbBits Bits per limb
 * @returns {bigint} The reconstructed value
 */
function fromLimbs(limbs, limbBits) {
  const shift = BigInt(limbBits);
  let value = 0n;
  for (let i = limbs.length - 1; i >= 0; i--) {
    value = (value << shift) + BigInt(limbs[i]);
  }
  return value;
}

// =============================================================================
// Reporting helpers
// =============================================================================

let failures = 0;
let passes = 0;
let skipped = 0;

/**
 * Prints a SKIP line. Deliberately distinct from PASS so an absent input file
 * can never be mistaken for a check that succeeded.
 *
 * @param {string} label Human-readable name of the check group
 * @param {string} reason Why it was skipped
 */
function skip(label, reason) {
  console.log(`[VERIFY] SKIP  ${label}`);
  console.log(`[VERIFY]       ${reason}`);
  skipped++;
}

/**
 * Prints a single pass/fail line and records failures for the exit code.
 *
 * @param {boolean} passed Whether the check succeeded
 * @param {string} label Human-readable name of the check
 * @param {string} [detail] Extra context printed underneath
 * @returns {boolean} The passed value, for chaining
 */
function check(passed, label, detail) {
  console.log(`[VERIFY] ${passed ? 'PASS' : 'FAIL'}  ${label}`);
  if (detail) {
    console.log(`[VERIFY]       ${detail}`);
  }
  if (passed) {
    passes++;
  } else {
    failures++;
  }
  return passed;
}

/**
 * Renders a buffer as an offset-prefixed hex dump with an ASCII gutter, so the
 * exact bytes that were hashed can be inspected by eye.
 *
 * @param {Buffer} buf Bytes to dump
 * @returns {string} Multi-line hex dump
 */
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

// =============================================================================
// Main
// =============================================================================

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
  const publicKeyPem = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
  const publicKey = crypto.createPublicKey(publicKeyPem);

  console.log('='.repeat(72));
  console.log('MOCK ISSUER CREDENTIAL - INDEPENDENT VERIFICATION');
  console.log('='.repeat(72));
  console.log(`Credential: ${CREDENTIAL_PATH}`);
  console.log(`Public key: ${PUBLIC_KEY_PATH}`);
  console.log('');

  // ---- Check 0: structure -------------------------------------------------
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

  // ---- Report the payload -------------------------------------------------
  console.log('');
  console.log('PAYLOAD');
  console.log('-'.repeat(72));
  for (const key of Object.keys(credential.payload).sort()) {
    console.log(`  ${key.padEnd(12)} ${credential.payload[key]}`);
  }

  // ---- Check 1: re-serialize and byte-compare -----------------------------
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

  // ---- Check 2: re-hash ---------------------------------------------------
  const recomputedHash = crypto.createHash('sha256').update(reserializedBytes).digest('hex');
  check(
    recomputedHash === credential.sha256,
    'Recomputed SHA-256 matches the stored hash',
    `recomputed ${recomputedHash}`
  );

  // ---- Check 3: signature verification ------------------------------------
  const signatureBytes = Buffer.from(credential.signature, 'hex');
  const signatureValid = crypto.verify(
    'sha256',
    reserializedBytes,
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    signatureBytes
  );
  check(
    signatureValid,
    'RSASSA-PKCS1-v1_5 signature verifies against mock_issuer_public.pem',
    `${signatureBytes.length}-byte signature, ${publicKey.asymmetricKeyDetails.modulusLength}-bit key, ` +
      `e=${publicKey.asymmetricKeyDetails.publicExponent}`
  );

  // ---- Check 4 & 5: negative controls -------------------------------------
  // A verifier that accepts everything would pass checks 1-3 just as happily.
  // These two prove the check above is actually discriminating.
  const tamperedMessage = Buffer.from(reserializedBytes);
  const flipIndex = Math.floor(tamperedMessage.length / 2);
  tamperedMessage[flipIndex] ^= 0x01;
  const tamperedMessageAccepted = crypto.verify(
    'sha256',
    tamperedMessage,
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    signatureBytes
  );
  check(
    !tamperedMessageAccepted,
    'Negative control: message with one flipped bit is REJECTED',
    `flipped low bit of byte ${flipIndex}`
  );

  const tamperedSignature = Buffer.from(signatureBytes);
  tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
  const tamperedSignatureAccepted = crypto.verify(
    'sha256',
    reserializedBytes,
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    tamperedSignature
  );
  check(
    !tamperedSignatureAccepted,
    'Negative control: signature with one flipped bit is REJECTED',
    'flipped low bit of the final signature byte'
  );

  // ---- Checks 7-11: circuit_inputs.json limb decomposition ----------------
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

    // 7. Geometry matches what RSAVerifier65537(121, 17) consumes. Compared
    //    against this script's own constants, not against the file's claims.
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

    // 8. Every limb is actually within range. A limb at or above 2^121 would be
    //    silently wrong: it still reconstructs correctly here, but overflows the
    //    circuit's Num2Bits(n) range check.
    const limit = 1n << BigInt(EXPECTED_LIMB_BITS);
    const allLimbs = [...(ci.modulus_limbs || []), ...(ci.signature_limbs || [])];
    const oversized = allLimbs.filter((l) => BigInt(l) >= limit).length;
    check(
      allLimbs.length > 0 && oversized === 0,
      `Every limb is < 2^${EXPECTED_LIMB_BITS} (in range for the circuit's Num2Bits check)`,
      `${allLimbs.length} limbs checked, ${oversized} out of range`
    );

    // 9. Modulus limbs reconstruct the modulus in the PUBLIC KEY - not the
    //    modulus_hex sitting next to them in the same file, which would only
    //    prove the file is self-consistent.
    const jwk = publicKey.export({ format: 'jwk' });
    const modulusFromPem = BigInt('0x' + Buffer.from(jwk.n, 'base64url').toString('hex'));
    const modulusFromLimbs = fromLimbs(ci.modulus_limbs || [], EXPECTED_LIMB_BITS);
    check(
      modulusFromLimbs === modulusFromPem,
      'Modulus limbs recombine to the modulus in mock_issuer_public.pem',
      `${modulusFromPem.toString(16).length * 4}-bit modulus, reconstructed from ${EXPECTED_LIMB_COUNT} limbs`
    );

    // 10. Signature limbs reconstruct the signature in the credential.
    const signatureFromLimbs = fromLimbs(ci.signature_limbs || [], EXPECTED_LIMB_BITS);
    const signatureFromCredential = BigInt('0x' + credential.signature);
    check(
      signatureFromLimbs === signatureFromCredential,
      'Signature limbs recombine to the signature in signed_credential.json',
      `${signatureBytes.length * 8}-bit signature, reconstructed from ${EXPECTED_LIMB_COUNT} limbs`
    );

    // 11. The byte array handed to the circuit is the same message that was
    //     signed, and the declared lengths match it.
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

    // 12. The padding is inside the signature, so it is part of what must be
    //     verified -- not cosmetic. Checks the fixed width, that the tail really
    //     is all 0x20, that the unpadded prefix still round-trips as JSON, and
    //     that SHA-256 stays at two blocks.
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

  // ---- Verdict ------------------------------------------------------------
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

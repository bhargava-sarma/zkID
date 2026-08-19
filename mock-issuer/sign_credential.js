#!/usr/bin/env node
/**
 * Mock issuer credential signing.
 *
 * Reads payload.json and the issuer private key, serializes the payload with a
 * strictly deterministic rule (see serializePayload below), hashes it with
 * SHA-256, signs the hash with RSASSA-PKCS1-v1_5, and writes:
 *
 *   signed_credential.json  - payload, exact serialized bytes, hash, signature
 *   circuit_inputs.json     - the same signature/modulus pre-chewed for Circom
 *
 * The byte sequence produced here is a hard contract with the Task 2 circuit.
 * Every rule that affects those bytes is asserted, not assumed.
 *
 * Usage:
 *   node sign_credential.js
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// =============================================================================
// Parameters
// =============================================================================

const REQUIRED_FIELDS = ['dob', 'gender', 'id_number', 'name'];

// Fixed signed-payload width. The circuit's byte array and SHA-256 instance are
// both sized to this constant, so it cannot vary per credential. 119 is the
// largest value that keeps SHA-256 at two blocks. See padToFixedLength.
const PAYLOAD_FIXED_BYTES = 119;
const PAD_CHAR = ' '; // 0x20

// RSA-2048 -> 256-byte signature and 256-byte modulus, split into limbs for
// Circom bigint arithmetic. 121 x 17 = 2057 bits, matching RSAVerifier65537(121, 17)
// from @zk-email/circuits.
//
// Why 121 and not 64: a limb must stay under half the ~254-bit circom field so that
// limb products cannot overflow, and 17 is the fewest 121-bit limbs that clear 2048.
// Fewer, wider limbs means far fewer cross-limb multiplications in the modular
// exponentiation -- measured at 190,945 constraints for 121x17 against the ~536k
// that a 64x32 layout costs. See experiments/rsa-baseline/.
const LIMB_BITS = 121;
const LIMB_COUNT = 17;

const PAYLOAD_PATH = path.join(__dirname, 'payload.json');
const PRIVATE_KEY_PATH = path.join(__dirname, 'mock_issuer_private.pem');
const PUBLIC_KEY_PATH = path.join(__dirname, 'mock_issuer_public.pem');
const CREDENTIAL_PATH = path.join(__dirname, 'signed_credential.json');
const CIRCUIT_INPUTS_PATH = path.join(__dirname, 'circuit_inputs.json');

// =============================================================================
// Payload validation
// =============================================================================

/**
 * Rejects any payload whose serialization would not be byte-predictable.
 *
 * The circuit hashes raw bytes, so anything that could introduce a JSON escape
 * sequence (a quote, a backslash, a control character) or multi-byte UTF-8 would
 * silently desynchronize the circuit from this script. Failing loudly here is
 * far cheaper than debugging a hash mismatch inside Circom.
 *
 * @param {object} payload Parsed payload.json
 * @throws {Error} If any rule is violated
 */
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
    // Printable ASCII only: guarantees UTF-8 bytes == ASCII bytes == characters.
    if (!/^[\x20-\x7E]+$/.test(value)) {
      throw new Error(
        `Field "${key}" contains a non-printable or non-ASCII character. ` +
          'Only printable ASCII (0x20-0x7E) is allowed, so the serialized byte ' +
          'length stays predictable for the circuit.'
      );
    }
    // Belt and braces: these two are the only printable ASCII characters that
    // JSON.stringify would escape, changing the byte count.
    if (value.includes('"') || value.includes('\\')) {
      throw new Error(
        `Field "${key}" contains a quote or backslash, which JSON escaping would ` +
          'expand. Not permitted.'
      );
    }
  }

  // Field-shape rules. These do not affect the byte contract, but a malformed
  // date or ID would produce a credential the demo circuits cannot interpret.
  if (!/^\d{4}-\d{2}-\d{2}$/.test(payload.dob)) {
    throw new Error(`Field "dob" must be YYYY-MM-DD, got "${payload.dob}".`);
  }
  if (!/^\d{12}$/.test(payload.id_number)) {
    throw new Error(`Field "id_number" must be exactly 12 digits.`);
  }
  if (!['M', 'F', 'O'].includes(payload.gender)) {
    throw new Error(`Field "gender" must be one of M, F, O. Got "${payload.gender}".`);
  }
}

// =============================================================================
// Canonical serialization - THE contract with the Task 2 circuit
// =============================================================================

/**
 * Serializes the payload to its canonical form, before padding.
 *
 * The rule, in full:
 *   1. The object has exactly the four permitted keys, no others.
 *   2. Keys are sorted ascending with JS default sort (UTF-16 code-unit order).
 *      For these ASCII keys that is plain lexicographic: dob, gender, id_number, name.
 *   3. JSON.stringify with NO space argument, so no whitespace is emitted anywhere -
 *      no spaces after ':' or ',', no newlines, no trailing newline.
 *   4. The result is encoded UTF-8. validatePayload has already guaranteed the
 *      content is printable ASCII, so UTF-8 encoding is byte-identical to ASCII.
 *
 * Insertion order of the rebuilt object is what drives JSON.stringify's output
 * order, which is why the keys are re-inserted in sorted order rather than
 * relying on the order they happened to appear in payload.json.
 *
 * @param {object} payload Validated payload
 * @returns {string} The canonical serialization
 */
function serializePayload(payload) {
  const ordered = {};
  for (const key of Object.keys(payload).sort()) {
    ordered[key] = payload[key];
  }
  return JSON.stringify(ordered);
}

/**
 * Pads the canonical serialization to the fixed width the circuit is built for.
 *
 * The circuit hardcodes its input array length and its SHA-256 width, so the
 * signed byte string must be a constant size regardless of how long the name or
 * other values are. 119 bytes is the largest payload that still fits two
 * SHA-256 blocks: 119*8 = 952 bits, and 952 + 1 + 64 = 1017 <= 1024. One more
 * byte forces a third block and costs ~31k extra constraints.
 *
 * Padding is trailing 0x20 (space) appended AFTER the closing brace. Three
 * properties make this the right choice:
 *   - Trailing whitespace is legal JSON, so the padded string still parses.
 *   - Space cannot introduce a second `"dob":"` occurrence, which the circuit's
 *     uniqueness scan asserts against.
 *   - It is printable, so it stays visible in a hex dump rather than looking
 *     like file corruption the way trailing NULs would.
 *
 * The padding is inside the signature: the issuer signs all 119 bytes. The
 * circuit hashes all 119 bytes and simply never looks at the tail.
 *
 * @param {string} serialized The canonical serialization
 * @returns {string} Exactly PAYLOAD_FIXED_BYTES bytes
 * @throws {Error} If the canonical form already exceeds the fixed width
 */
function padToFixedLength(serialized) {
  const length = Buffer.byteLength(serialized, 'utf8');
  if (length > PAYLOAD_FIXED_BYTES) {
    throw new Error(
      `Canonical payload is ${length} bytes, over the ${PAYLOAD_FIXED_BYTES}-byte fixed width. ` +
        'Shorten a field value, or rebuild the circuit for a larger width (note that going ' +
        'past 119 bytes forces a third SHA-256 block).'
    );
  }
  return serialized + PAD_CHAR.repeat(PAYLOAD_FIXED_BYTES - length);
}

// =============================================================================
// Circom helpers
// =============================================================================

/**
 * Converts a big-endian byte buffer to a BigInt.
 *
 * @param {Buffer} buf Big-endian bytes
 * @returns {bigint}
 */
function bufferToBigInt(buf) {
  return buf.length === 0 ? 0n : BigInt('0x' + buf.toString('hex'));
}

/**
 * Splits a BigInt into fixed-width limbs, least-significant limb first.
 *
 * This is the layout the common Circom bigint templates expect (zk-email's
 * RSAVerifier65537, circom-rsa-verify): an array of k limbs of n bits each, with
 * index 0 holding the low-order bits. Byte-identical to what zk-email's own
 * bigIntToChunkedBytes helper produces for the same value. Values are emitted as
 * decimal strings because a 121-bit limb exceeds Number.MAX_SAFE_INTEGER and would
 * lose precision as a JSON number.
 *
 * @param {bigint} value The value to split
 * @param {number} limbBits Bits per limb
 * @param {number} limbCount Number of limbs
 * @returns {string[]} Decimal-string limbs, least significant first
 */
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

// =============================================================================
// Output
// =============================================================================

/**
 * Writes a file by way of a temp file plus a rename.
 *
 * rename(2) within a filesystem is atomic, so a reader either sees the whole
 * previous file or the whole new one - never a half-written JSON document,
 * even if the process dies mid-write.
 *
 * @param {string} filePath Destination path
 * @param {string} contents Full file contents
 */
function writeAtomic(filePath, contents) {
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, contents);
  fs.renameSync(tmpPath, filePath);
}

// =============================================================================
// Main
// =============================================================================

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

  // ---- Serialize and pad --------------------------------------------------
  // `serialized` below is the PADDED form: it is what gets hashed and signed,
  // which is what signed_credential.json's `serialized` field has always meant.
  const canonical = serializePayload(payload);
  const serialized = padToFixedLength(canonical);
  const serializedBytes = Buffer.from(serialized, 'utf8');
  console.log(`[SIGN] Canonical: ${Buffer.byteLength(canonical, 'utf8')} bytes`);
  console.log(`[SIGN] ${canonical}`);
  console.log(
    `[SIGN] Padded:    ${serializedBytes.length} bytes / ${serializedBytes.length * 8} bits ` +
      `(+${PAYLOAD_FIXED_BYTES - Buffer.byteLength(canonical, 'utf8')} x 0x20)`
  );

  // ---- Hash ---------------------------------------------------------------
  const sha256Hex = crypto.createHash('sha256').update(serializedBytes).digest('hex');
  console.log(`[SIGN] SHA-256: ${sha256Hex}`);

  // ---- Sign ---------------------------------------------------------------
  const privateKey = crypto.createPrivateKey(fs.readFileSync(PRIVATE_KEY_PATH, 'utf8'));

  // crypto.sign digests the input itself, so it is handed the raw serialized
  // bytes rather than the digest. RSA_PKCS1_PADDING is Node's default for RSA
  // keys, but it is passed explicitly so the scheme is visible at the call site
  // and cannot drift if a future Node changes its default.
  const signature = crypto.sign('sha256', serializedBytes, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });
  const signatureHex = signature.toString('hex');
  console.log(`[SIGN] Signature: ${signature.length} bytes (${signatureHex.substring(0, 32)}...)`);

  // ---- Build signed_credential.json (in memory) ---------------------------
  // Nothing is written to disk until BOTH documents have been built. The limb
  // decomposition below can throw - on a bad exponent or a value that does not
  // fit the limb geometry - and writing the credential before that point would
  // leave a fresh credential paired with a stale or missing circuit_inputs.json.
  const credential = {
    payload,
    serialized,
    sha256: sha256Hex,
    signature: signatureHex,
  };

  // ---- Build circuit_inputs.json (in memory) ------------------------------
  const publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'));
  const jwk = publicKey.export({ format: 'jwk' });
  const modulusBytes = Buffer.from(jwk.n, 'base64url');
  const exponent = Number(bufferToBigInt(Buffer.from(jwk.e, 'base64url')));

  if (exponent !== 65537) {
    throw new Error(
      `Public exponent is ${exponent}, but the Circom RSA templates require 65537. ` +
        'Regenerate the keypair with generate_keypair.js.'
    );
  }

  const modulusBigInt = bufferToBigInt(modulusBytes);
  const signatureBigInt = bufferToBigInt(signature);

  const circuitInputs = {
    _comment:
      'Generated by sign_credential.js. Convenience derivations of signed_credential.json ' +
      'for the Task 2 Circom circuit. Nothing here is authoritative - signed_credential.json ' +
      'and mock_issuer_public.pem are the source of truth.',
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
      encoding: 'decimal string (values exceed Number.MAX_SAFE_INTEGER)',
    },
    // Fixed by PAYLOAD_FIXED_BYTES, not by the payload contents - the circuit's
    // input array and Sha256(n) width are both built to these constants.
    payload_byte_length: serializedBytes.length,
    payload_bit_length: serializedBytes.length * 8,
    sha256_block_count: Math.ceil((serializedBytes.length * 8 + 1 + 64) / 512),
    padding: {
      scheme: 'trailing 0x20 (space) appended after the closing brace',
      canonical_byte_length: Buffer.byteLength(canonical, 'utf8'),
      pad_byte_count: PAYLOAD_FIXED_BYTES - Buffer.byteLength(canonical, 'utf8'),
      note: 'padding is covered by the signature; the circuit hashes it and ignores it',
    },
    modulus_hex: modulusBytes.toString('hex'),
    exponent,
    modulus_limbs: toLimbs(modulusBigInt, LIMB_BITS, LIMB_COUNT),
    signature_limbs: toLimbs(signatureBigInt, LIMB_BITS, LIMB_COUNT),
    // The message the circuit hashes, one byte per array element.
    message_bytes: Array.from(serializedBytes),
  };
  // ---- Commit both to disk ------------------------------------------------
  // Past this line every value is computed and nothing else can throw, so the
  // two files cannot diverge. Serializing before either write keeps the window
  // between them to two rename(2) calls.
  const credentialJson = JSON.stringify(credential, null, 2) + '\n';
  const circuitInputsJson = JSON.stringify(circuitInputs, null, 2) + '\n';

  writeAtomic(CREDENTIAL_PATH, credentialJson);
  console.log(`[SIGN] Wrote ${path.basename(CREDENTIAL_PATH)}`);
  writeAtomic(CIRCUIT_INPUTS_PATH, circuitInputsJson);
  console.log(`[SIGN] Wrote ${path.basename(CIRCUIT_INPUTS_PATH)}`);

  console.log(
    `[SIGN] Circuit sizing: ${circuitInputs.payload_bit_length} message bits, ` +
      `${circuitInputs.sha256_block_count} SHA-256 block(s)`
  );
  console.log('[SIGN] Next: node verify_credential.js');
}

try {
  main();
} catch (err) {
  // Validation and key-parsing failures are expected operator errors, not bugs.
  // A one-line message is more useful here than a stack trace.
  console.error(`[SIGN] ERROR: ${err.message}`);
  process.exit(1);
}

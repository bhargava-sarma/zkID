/**
 * Live credential signing from OCR output.
 *
 * Turns fields OCR just extracted into a canonically-serialized payload, signs
 * it with the mock issuer's private key at request time, and produces the
 * composed circuit's inputs. This is the path where a proof attests to what an
 * ISSUER signed, rather than to a value this server computed about itself.
 *
 * The validation, serialization, padding and limb decomposition are all
 * imported from mock-issuer/sign_credential.js rather than reimplemented. If
 * they were copied, a change to the byte contract would silently desynchronize
 * the signer from the circuit.
 *
 * RAW ID HANDLING. The 12-digit number is required to build the payload -- the
 * canonical format demands literal digits and the guard is /^\d{12}$/, so a hash
 * cannot stand in. It exists only as a local in this module and inside the
 * signed byte string, which is a PRIVATE circuit input. It is never written to
 * disk, never logged (see maskId), and never passed to storeUser. The signed
 * credential itself is returned to the caller in memory and not persisted.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MOCK_ISSUER_DIR = path.join(__dirname, '..', 'mock-issuer');

// Reused, not reimplemented -- one implementation of the byte contract.
const {
  validatePayload,
  serializePayload,
  padToFixedLength,
  toLimbs,
  bufferToBigInt,
  LIMB_BITS,
  LIMB_COUNT,
  PAYLOAD_FIXED_BYTES,
} = require(path.join(MOCK_ISSUER_DIR, 'sign_credential.js'));

const PRIVATE_KEY_PATH = path.join(MOCK_ISSUER_DIR, 'mock_issuer_private.pem');
const PUBLIC_KEY_PATH = path.join(MOCK_ISSUER_DIR, 'mock_issuer_public.pem');

// =============================================================================
// Errors
// =============================================================================

/**
 * A failure with a user-facing message and a machine-readable reason.
 *
 * `detail` is for server logs only -- guard messages quote field contents.
 */
class CredentialError extends Error {
  constructor({ code, reason, userMessage, detail, retryable, status }) {
    super(userMessage);
    this.name = 'CredentialError';
    this.code = code;
    this.reason = reason;
    this.userMessage = userMessage;
    this.detail = detail;
    this.retryable = retryable;
    this.status = status;
  }
}

const UNPROCESSABLE =
  'We could not generate a verifiable credential from this image. ' +
  'Please retake the photo in good light with the whole card visible.';

/**
 * @param {string} reason Machine-readable cause
 * @param {string} detail Server-log-only detail
 */
function unprocessable(reason, detail) {
  return new CredentialError({
    code: 'CREDENTIAL_UNPROCESSABLE',
    reason,
    userMessage: UNPROCESSABLE,
    detail,
    retryable: true,
    status: 422,
  });
}

// =============================================================================
// OCR -> canonical payload
// =============================================================================

// OCR emits 'Male' | 'Female' | 'Other' | null. There is deliberately no
// default: signing a guessed gender would put a fabricated claim inside an
// issuer-attested credential, which is the opposite of what this path is for.
const GENDER_MAP = { male: 'M', female: 'F', other: 'O', transgender: 'O' };

/** Masks an id for logging. Never log the raw value. */
function maskId(id) {
  return typeof id === 'string' && id.length >= 4 ? `********${id.slice(-4)}` : '****';
}

/**
 * Adapts OCR output to the canonical payload the mock issuer signs.
 *
 * Stricter than preprocessing.js on purpose. preprocessData builds its ISO date
 * with an unvalidated split('/'), so an OCR misread like "O1/O1/199O" (letter O
 * for zero) yields "199O-O1-O1" and a NaN encoding. Here that is rejected with a
 * named reason instead of flowing onward.
 *
 * @param {{name: string, dob: string, aadhaarNumber: string, gender: string|null}} ocr
 * @returns {{name: string, dob: string, id_number: string, gender: string}}
 * @throws {CredentialError}
 */
function buildCanonicalPayload(ocr) {
  const { name, dob, aadhaarNumber, gender } = ocr || {};

  // --- name ---
  if (typeof name !== 'string' || name.trim().length === 0) {
    throw unprocessable('name_missing', 'OCR produced no usable name.');
  }
  const cleanName = name.trim().replace(/\s+/g, ' ');

  // --- dob: DD/MM/YYYY -> YYYY-MM-DD, strictly ---
  if (typeof dob !== 'string') {
    throw unprocessable('dob_missing', 'OCR produced no date of birth.');
  }
  const m = dob.trim().match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!m) {
    throw unprocessable(
      'dob_format',
      `DOB "${dob}" is not DD/MM/YYYY. A letter-for-digit OCR misread (O for 0) looks like this.`
    );
  }
  const [, dd, mm, yyyy] = m;
  const isoDob = `${yyyy}-${mm}-${dd}`;

  // --- id_number: 12 digits, whitespace stripped ---
  if (typeof aadhaarNumber !== 'string') {
    throw unprocessable('id_number_missing', 'OCR produced no ID number.');
  }
  const idDigits = aadhaarNumber.replace(/\s/g, '');
  if (!/^\d{12}$/.test(idDigits)) {
    throw unprocessable(
      'id_number_format',
      `ID number did not reduce to 12 digits (got ${idDigits.length} chars, ${maskId(idDigits)}).`
    );
  }

  // --- gender: hard failure when undetected ---
  if (!gender) {
    throw unprocessable(
      'gender_missing',
      'OCR did not detect a gender. Not defaulted: a guessed value would be signed as issuer-attested fact.'
    );
  }
  const genderCode = GENDER_MAP[String(gender).toLowerCase()];
  if (!genderCode) {
    throw unprocessable('gender_invalid', `Unrecognized gender "${gender}".`);
  }

  return { name: cleanName, dob: isoDob, id_number: idDigits, gender: genderCode };
}

// =============================================================================
// Signing
// =============================================================================

/**
 * Validates, serializes, pads and signs a canonical payload, and derives the
 * composed circuit's inputs.
 *
 * Nothing here touches the filesystem except reading the issuer keys.
 *
 * @param {object} payload Canonical payload from buildCanonicalPayload
 * @returns {{credential: object, circuitInputs: object, canonicalBytes: number}}
 * @throws {CredentialError}
 */
function signCredential(payload) {
  // The mock issuer's own guards, imported. Any failure here means OCR produced
  // something that cannot be represented in the signed format.
  try {
    validatePayload(payload);
  } catch (err) {
    throw unprocessable(guardReason(err.message), err.message);
  }

  const canonical = serializePayload(payload);
  let serialized;
  try {
    serialized = padToFixedLength(canonical);
  } catch (err) {
    // Only reachable when the canonical form exceeds the fixed width -- in
    // practice a name long enough to push past 119 bytes.
    throw unprocessable('payload_too_long', err.message);
  }

  const serializedBytes = Buffer.from(serialized, 'utf8');
  const sha256Hex = crypto.createHash('sha256').update(serializedBytes).digest('hex');

  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(fs.readFileSync(PRIVATE_KEY_PATH, 'utf8'));
  } catch (err) {
    throw new CredentialError({
      code: 'PROVING_UNAVAILABLE',
      reason: 'issuer_key_unavailable',
      userMessage: 'Verification is temporarily unavailable. Please try again shortly.',
      detail: `Could not load the issuer private key: ${err.message}`,
      retryable: false,
      status: 500,
    });
  }

  const signature = crypto.sign('sha256', serializedBytes, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });

  const publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'));
  const jwk = publicKey.export({ format: 'jwk' });
  const modulusBytes = Buffer.from(jwk.n, 'base64url');

  const circuitInputs = {
    payload_byte_length: serializedBytes.length,
    payload_bit_length: serializedBytes.length * 8,
    sha256_block_count: Math.ceil((serializedBytes.length * 8 + 1 + 64) / 512),
    padding: {
      canonical_byte_length: Buffer.byteLength(canonical, 'utf8'),
      pad_byte_count: PAYLOAD_FIXED_BYTES - Buffer.byteLength(canonical, 'utf8'),
    },
    modulus_limbs: toLimbs(bufferToBigInt(modulusBytes), LIMB_BITS, LIMB_COUNT),
    signature_limbs: toLimbs(bufferToBigInt(signature), LIMB_BITS, LIMB_COUNT),
    message_bytes: Array.from(serializedBytes),
  };

  // Deliberately NOT logging the canonical payload: it contains the raw id.
  console.log(
    `[CREDENTIAL] Signed — ${Buffer.byteLength(canonical, 'utf8')} canonical + ` +
      `${circuitInputs.padding.pad_byte_count} pad = ${serializedBytes.length} bytes, ` +
      `sha256 ${sha256Hex.substring(0, 12)}..., id ${maskId(payload.id_number)}`
  );

  return {
    credential: { sha256: sha256Hex, signature: signature.toString('hex') },
    circuitInputs,
    canonicalBytes: Buffer.byteLength(canonical, 'utf8'),
  };
}

/** Maps a guard message to a machine-readable reason. */
function guardReason(message) {
  if (/dob/i.test(message)) return 'dob_format';
  if (/id_number/i.test(message)) return 'id_number_format';
  if (/gender/i.test(message)) return 'gender_invalid';
  if (/non-printable|non-ASCII/i.test(message)) return 'name_invalid_chars';
  if (/quote or backslash/i.test(message)) return 'name_invalid_chars';
  if (/must not be empty/i.test(message)) return 'field_empty';
  return 'payload_invalid';
}

module.exports = { buildCanonicalPayload, signCredential, CredentialError, maskId };

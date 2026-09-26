// OCR fields -> canonical payload -> RSA signature -> composed-circuit inputs.
// The raw 12-digit ID lives only in memory and in the signed bytes (a private
// circuit input). It is never logged in full, written to disk, or stored.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MOCK_ISSUER_DIR = path.join(__dirname, '..', 'mock-issuer');

// Shared with the mock issuer so there is one implementation of the byte format.
const {
  validatePayload,
  serializePayload,
  padToFixedLength,
  signBytes,
  buildCircuitInputs,
} = require(path.join(MOCK_ISSUER_DIR, 'sign_credential.js'));

const PRIVATE_KEY_PATH = path.join(MOCK_ISSUER_DIR, 'mock_issuer_private.pem');
const PUBLIC_KEY_PATH = path.join(MOCK_ISSUER_DIR, 'mock_issuer_public.pem');

// `detail` is for server logs only: guard messages quote field contents.
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

function unprocessable(reason, detail) {
  return new CredentialError({
    code: 'CREDENTIAL_UNPROCESSABLE',
    reason,
    userMessage:
      'We could not generate a verifiable credential from this image. ' +
      'Please retake the photo in good light with the whole card visible.',
    detail,
    retryable: true,
    status: 422,
  });
}

function unavailable(reason, detail) {
  return new CredentialError({
    code: 'PROVING_UNAVAILABLE',
    reason,
    userMessage: 'Verification is temporarily unavailable. Please try again shortly.',
    detail,
    retryable: false,
    status: 500,
  });
}

// No default: a guessed gender would be signed as issuer-attested fact.
const GENDER_MAP = { male: 'M', female: 'F', other: 'O', transgender: 'O' };

function maskId(id) {
  return typeof id === 'string' && id.length >= 4 ? `********${id.slice(-4)}` : '****';
}

// Strict: an OCR misread like "O1/O1/199O" is rejected, not passed through.
function buildCanonicalPayload(ocr) {
  const { name, dob, aadhaarNumber, gender } = ocr || {};

  if (typeof name !== 'string' || name.trim().length === 0) {
    throw unprocessable('name_missing', 'OCR produced no usable name.');
  }
  const cleanName = name.trim().replace(/\s+/g, ' ');

  if (typeof dob !== 'string') {
    throw unprocessable('dob_missing', 'OCR produced no date of birth.');
  }
  const m = dob.trim().match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!m) {
    throw unprocessable('dob_format', `DOB "${dob}" is not DD/MM/YYYY.`);
  }
  const [, dd, mm, yyyy] = m;

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

  if (!gender) {
    throw unprocessable('gender_missing', 'OCR did not detect a gender.');
  }
  const genderCode = GENDER_MAP[String(gender).toLowerCase()];
  if (!genderCode) {
    throw unprocessable('gender_invalid', `Unrecognized gender "${gender}".`);
  }

  return { name: cleanName, dob: `${yyyy}-${mm}-${dd}`, id_number: idDigits, gender: genderCode };
}

function guardReason(message) {
  if (/calendar date/i.test(message)) return 'dob_invalid';
  if (/dob/i.test(message)) return 'dob_format';
  if (/id_number/i.test(message)) return 'id_number_format';
  if (/gender/i.test(message)) return 'gender_invalid';
  if (/non-printable|non-ASCII|quote or backslash/i.test(message)) return 'name_invalid_chars';
  if (/must not be empty/i.test(message)) return 'field_empty';
  return 'payload_invalid';
}

function signCredential(payload) {
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
    throw unprocessable('payload_too_long', err.message);
  }

  let privateKey;
  let publicKey;
  try {
    privateKey = crypto.createPrivateKey(fs.readFileSync(PRIVATE_KEY_PATH, 'utf8'));
    publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY_PATH, 'utf8'));
  } catch (err) {
    throw unavailable('issuer_key_unavailable', `Could not load the issuer keys: ${err.message}`);
  }

  const serializedBytes = Buffer.from(serialized, 'utf8');
  const sha256Hex = crypto.createHash('sha256').update(serializedBytes).digest('hex');
  const signature = signBytes(serializedBytes, privateKey);
  const circuitInputs = buildCircuitInputs(canonical, serializedBytes, signature, publicKey);
  const canonicalBytes = circuitInputs.padding.canonical_byte_length;

  // Never log the canonical payload: it contains the raw ID.
  console.log(
    `[CREDENTIAL] Signed — ${canonicalBytes} canonical + ` +
      `${circuitInputs.padding.pad_byte_count} pad = ${serializedBytes.length} bytes, ` +
      `sha256 ${sha256Hex.substring(0, 12)}..., id ${maskId(payload.id_number)}`
  );

  return {
    credential: { sha256: sha256Hex, signature: signature.toString('hex') },
    circuitInputs,
    canonicalBytes,
  };
}

module.exports = { buildCanonicalPayload, signCredential, CredentialError, unavailable };

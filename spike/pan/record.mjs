// A DigiLocker PAN Verification Record (XML), read and checked outside the
// circuit, and the circuit input for it. Every failure throws a PanError with
// a code; nothing falls back. Nothing here logs or returns the record's values
// except `values`, which only the tests read.

import crypto from 'node:crypto';
import { DOMParser } from '@xmldom/xmldom';
import { ExclusiveCanonicalization } from 'xml-crypto';
import { keyHashFromModulus } from '../../packages/circuit/input.mjs';
import { poseidon4 } from 'poseidon-lite/poseidon4';
import { DIGEST_B64_LENGTH, DOB_OFFSET, DOC_HEAD, FIELD_WINDOW_BYTES, GENDER_VALUES, MAX_DOC_BYTES, PAN_LENGTH, PAN_OFFSET, signedInfoFor } from './format.mjs';

export class PanError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'PanError';
    this.code = code;
  }
}

const DSIG = 'http://www.w3.org/2000/09/xmldsig#';
const c14n = (node) => new ExclusiveCanonicalization().process(node, {}).toString();
const text = (parent, name) => parent.getElementsByTagNameNS(DSIG, name)[0]?.textContent?.replace(/\s+/g, '') ?? '';

export const LIMB_BITS = 121;
export const LIMBS = 17;
const limbs = (value) => Array.from({ length: LIMBS }, (_, i) => ((value >> (BigInt(LIMB_BITS) * BigInt(i))) & ((1n << BigInt(LIMB_BITS)) - 1n)).toString());

// Reads and checks a record: its signature under the certificate it carries,
// DigiLocker's exact SignedInfo, the fixed head, and where its fields are.
// `strict: false` skips the layout checks, for tests that hand the circuit a
// signed record outside its layout.
export function readRecord(xml, { strict = true } = {}) {
  let document;
  try {
    document = new DOMParser({ onError: (level, message) => { throw new Error(message); } }).parseFromString(xml, 'text/xml');
  } catch (err) {
    throw new PanError('NOT_XML', `the file is not well-formed XML (${err.message})`);
  }
  const root = document.documentElement;
  const signatures = root?.getElementsByTagNameNS(DSIG, 'Signature');
  if (!root || root.localName !== 'Certificate' || signatures.length !== 1 || signatures[0].parentNode !== root) {
    throw new PanError('NOT_A_RECORD', 'expected a <Certificate> with one enveloped <Signature>');
  }
  const signatureNode = signatures[0];
  const digestB64 = text(signatureNode, 'DigestValue');
  const signedInfo = c14n(signatureNode.getElementsByTagNameNS(DSIG, 'SignedInfo')[0]);
  if (digestB64.length !== DIGEST_B64_LENGTH || signedInfo !== signedInfoFor(digestB64)) {
    throw new PanError('UNSUPPORTED_SIGNED_INFO', "SignedInfo is not DigiLocker's (exclusive c14n, RSA-SHA1, SHA-256, enveloped)");
  }

  let certificate;
  try {
    certificate = new crypto.X509Certificate(Buffer.from(text(signatureNode, 'X509Certificate'), 'base64'));
  } catch {
    throw new PanError('BAD_CERTIFICATE', 'the record carries no readable X.509 certificate');
  }
  const { modulusLength, publicExponent } = certificate.publicKey.asymmetricKeyDetails ?? {};
  if (certificate.publicKey.asymmetricKeyType !== 'rsa' || modulusLength !== 2048 || publicExponent !== 65537n) {
    throw new PanError('UNSUPPORTED_KEY', 'the circuit verifies RSA-2048 with exponent 65537 only');
  }
  const signature = Buffer.from(text(signatureNode, 'SignatureValue'), 'base64');
  if (!crypto.verify('sha1', Buffer.from(signedInfo, 'utf8'), certificate.publicKey, signature)) {
    throw new PanError('BAD_SIGNATURE', 'the signature does not verify under the certificate it carries');
  }

  root.removeChild(signatureNode);
  const canonical = c14n(root);
  const doc = Buffer.from(canonical, 'utf8');
  if (crypto.createHash('sha256').update(doc).digest('base64') !== digestB64) {
    throw new PanError('DIGEST_MISMATCH', 'the record does not match the digest its signature covers');
  }

  const [head, , rest] = DOC_HEAD;
  if (strict && (!canonical.startsWith(head) || canonical.slice(PAN_OFFSET + PAN_LENGTH, DOB_OFFSET) !== rest)) {
    throw new PanError('UNSUPPORTED_RECORD', 'not a PAN Verification Record in the layout the circuit reads (DigiLocker, Income Tax Department, status A)');
  }
  const genderAt = canonical.indexOf(' gender="', DOB_OFFSET);
  const uidAt = canonical.indexOf(' uid="', genderAt);
  const panAt = canonical.indexOf('<PAN num="', uidAt);
  if (genderAt < 0 || uidAt < 0 || panAt < 0 || panAt + 61 > FIELD_WINDOW_BYTES) {
    throw new PanError('UNSUPPORTED_RECORD', `gender, uid and <PAN> must lie within the record's first ${FIELD_WINDOW_BYTES} bytes`);
  }
  const attribute = (at, tag, length) => canonical.slice(at + tag.length, at + tag.length + length);
  const values = {
    pan: canonical.slice(PAN_OFFSET, PAN_OFFSET + PAN_LENGTH),
    dob: canonical.slice(DOB_OFFSET, DOB_OFFSET + 10),
    gender: canonical.slice(genderAt + 9, canonical.indexOf('"', genderAt + 9)),
    uid: attribute(uidAt, ' uid="', 32),
    verifiedOn: attribute(panAt + 20, '" verifiedOn="', 19),
  };
  if (strict) {
    if (!Object.hasOwn(GENDER_VALUES, values.gender)) throw new PanError('UNSUPPORTED_RECORD', 'gender is not MALE, FEMALE or TRANSGENDER');
    if (!/^[0-9a-f]{32}$/.test(values.uid)) throw new PanError('UNSUPPORTED_RECORD', 'uid is not 32 hex characters');
    if (attribute(panAt, '<PAN num="', PAN_LENGTH) !== values.pan) throw new PanError('UNSUPPORTED_RECORD', 'the two PAN numbers differ');
  }

  const modulus = BigInt(`0x${Buffer.from(certificate.publicKey.export({ format: 'jwk' }).n, 'base64url').toString('hex')}`);
  return { doc, signature, modulus, hints: { genderAt, uidAt, panAt }, values, certificate };
}

// SHA-256 padding, then zeros to the circuit's size.
function padDoc(doc) {
  const paddedLength = Math.ceil((doc.length + 9) / 64) * 64;
  if (paddedLength > MAX_DOC_BYTES) throw new PanError('RECORD_TOO_LONG', `the record takes ${paddedLength} padded bytes; the circuit takes ${MAX_DOC_BYTES}`);
  const padded = new Uint8Array(MAX_DOC_BYTES);
  padded.set(doc);
  padded[doc.length] = 0x80;
  new DataView(padded.buffer).setBigUint64(paddedLength - 8, BigInt(doc.length) * 8n);
  return { padded, paddedLength };
}

export function circuitInput(record, { dobCutoff, nullifierSeed, signalHash, revealGender = false }) {
  const { padded, paddedLength } = padDoc(record.doc);
  return {
    doc: Array.from(padded, String),
    docPaddedLength: String(paddedLength),
    signature: limbs(BigInt(`0x${record.signature.toString('hex')}`)),
    modulus: limbs(record.modulus),
    genderAt: String(record.hints.genderAt),
    uidAt: String(record.hints.uidAt),
    panAt: String(record.hints.panAt),
    revealGender: revealGender ? '1' : '0',
    dobCutoff: String(dobCutoff),
    nullifierSeed: String(nullifierSeed),
    signalHash: String(signalHash),
  };
}

// The circuit's public signals, in snarkjs order: outputs, then public inputs.
export const PUBLIC_SIGNALS = ['pubkeyHash', 'nullifier', 'verifiedHour', 'bornBy', 'gender', 'dobCutoff', 'nullifierSeed', 'signalHash'];

const pack = (ascii) => [...Buffer.from(ascii, 'latin1')].reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
const ymd = (ddmmyyyy) => Number(`${ddmmyyyy.slice(6, 10)}${ddmmyyyy.slice(3, 5)}${ddmmyyyy.slice(0, 2)}`);

// What the circuit outputs for a record, computed in JavaScript, for the tests.
export function expectedOutputs(record, { dobCutoff, nullifierSeed, revealGender = false }) {
  const { values } = record;
  return {
    pubkeyHash: keyHashFromModulus(record.modulus),
    nullifier: poseidon4([BigInt(nullifierSeed), pack(values.pan), pack(values.uid.slice(0, 16)), pack(values.uid.slice(16))]).toString(),
    verifiedHour: String(ymd(values.verifiedOn) * 100 + Number(values.verifiedOn.slice(11, 13))),
    bornBy: ymd(values.dob) <= Number(dobCutoff) ? '1' : '0',
    gender: revealGender ? String(GENDER_VALUES[values.gender].charCodeAt(0)) : '0',
  };
}

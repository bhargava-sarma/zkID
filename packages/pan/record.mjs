// A DigiLocker PAN Verification Record (XML), read and checked with WebCrypto
// and plain JavaScript only, so the holder app and the tests run the same code:
// the XML is parsed with @xmldom/xmldom and canonicalized (c14n.mjs), its
// digest is checked, DigiLocker's signature is checked against the keys the
// caller trusts, and its layout against what the circuit reads. Every failure
// throws a PanError with a code; nothing falls back. The record's values are
// returned for the caller to use and show; nothing here logs them.

import { DOMParser } from '@xmldom/xmldom';
import { C14nError, canonicalize } from './c14n.mjs';
import { DIGEST_B64_LENGTH, DOB_OFFSET, DOC_HEAD, FIELD_WINDOW_BYTES, GENDER_VALUES, MAX_DOC_BYTES, PAN_LENGTH, PAN_OFFSET, signedInfoFor } from './format.mjs';

export class PanError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PanError';
    this.code = code;
  }
}

const DSIG = 'http://www.w3.org/2000/09/xmldsig#';
// How DigiLocker signs: what SignedInfo names, element by element.
const ALGORITHMS = {
  CanonicalizationMethod: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  SignatureMethod: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
  Transform: 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
  DigestMethod: 'http://www.w3.org/2001/04/xmlenc#sha256',
};
const MAX_XML = 64 * 1024; // a record is about 6 KB
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const fromBase64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const toBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
const fromHex = (hex) => Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));

// A trusted key, for checking DigiLocker's RSA-SHA1 signature in WebCrypto.
export function importSigningKey(modulusHex) {
  const n = toBase64(fromHex(modulusHex)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return crypto.subtle.importKey('jwk', { kty: 'RSA', n, e: 'AQAB', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' }, false, ['verify']);
}

function parse(xml) {
  if (typeof xml !== 'string' || xml.length > MAX_XML) throw new PanError('NOT_XML', `Expected the text of a record's XML, up to ${MAX_XML / 1024} KB.`);
  let document;
  try {
    document = new DOMParser({
      onError: (level, message) => {
        throw new Error(message);
      },
    }).parseFromString(xml, 'text/xml');
  } catch {
    throw new PanError('NOT_XML', 'This file is not well-formed XML.');
  }
  if (Array.from(document.childNodes).some((node) => node.nodeType === 10)) {
    throw new PanError('NOT_XML', 'This XML declares a document type, which a DigiLocker record does not.');
  }
  return document;
}

// The first position of `needle` in `bytes` at or after `from`, or -1.
function indexOf(bytes, needle, from = 0) {
  outer: for (let i = Math.max(0, from); i + needle.length <= bytes.length; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

// keys: [{ id, label, modulus (hex), notBefore, notAfter, cryptoKey? }]. The
// record's signer is the first whose key verifies DigiLocker's signature.
// `strict: false` skips the layout checks, for tests that hand the circuit a
// signed record outside its layout.
export async function readRecord(xml, keys, { strict = true } = {}) {
  const document = parse(xml);
  const root = document.documentElement;
  const signatures = root ? root.getElementsByTagNameNS(DSIG, 'Signature') : [];
  if (!root || root.localName !== 'Certificate' || root.namespaceURI || signatures.length !== 1 || signatures[0].parentNode !== root) {
    throw new PanError('NOT_A_RECORD', 'This is not a DigiLocker record: expected a <Certificate> with one signature.');
  }
  const signatureNode = signatures[0];
  const first = (name) => signatureNode.getElementsByTagNameNS(DSIG, name)[0];
  for (const [name, algorithm] of Object.entries(ALGORITHMS)) {
    if (first(name)?.getAttribute('Algorithm') !== algorithm) {
      throw new PanError('UNSUPPORTED_SIGNATURE', 'This record is signed in a way this app does not read (not RSA-SHA1 over SHA-256 with exclusive canonicalization).');
    }
  }
  const digestB64 = (first('DigestValue')?.textContent ?? '').replace(/\s+/g, '');
  const signatureB64 = (first('SignatureValue')?.textContent ?? '').replace(/\s+/g, '');
  if (digestB64.length !== DIGEST_B64_LENGTH || !BASE64.test(digestB64) || !BASE64.test(signatureB64)) {
    throw new PanError('NOT_A_RECORD', "This record's signature is malformed.");
  }

  root.removeChild(signatureNode);
  let canonical;
  try {
    canonical = canonicalize(root);
  } catch (err) {
    if (err instanceof C14nError) throw new PanError('UNSUPPORTED_RECORD', `This record holds XML this app cannot read (${err.message}).`);
    throw err;
  }
  const doc = encoder.encode(canonical);
  if (toBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', doc))) !== digestB64) {
    throw new PanError('DIGEST_MISMATCH', 'This record was changed after it was signed.');
  }

  // The circuit hashes DigiLocker's SignedInfo as format.mjs writes it, so the
  // signature must verify over exactly those bytes.
  const signedInfo = encoder.encode(signedInfoFor(digestB64));
  const signature = fromBase64(signatureB64);
  let signer = null;
  for (const key of keys) {
    const cryptoKey = key.cryptoKey ?? (await importSigningKey(key.modulus));
    if (await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, signedInfo)) {
      signer = key;
      break;
    }
  }
  if (!signer) throw new PanError('UNTRUSTED_RECORD', 'This record is not signed by DigiLocker (no trusted key verifies it).');

  const paddedLength = Math.ceil((doc.length + 9) / 64) * 64;
  if (paddedLength > MAX_DOC_BYTES) throw new PanError('RECORD_TOO_LONG', `This record is ${doc.length} bytes; the circuit reads at most ${MAX_DOC_BYTES - 9}.`);
  const unsupported = (why) => new PanError('UNSUPPORTED_RECORD', `This record is not in the layout the circuit reads: ${why}.`);
  const [head, , rest] = DOC_HEAD;
  if (strict && (decoder.decode(doc.subarray(0, PAN_OFFSET)) !== head || decoder.decode(doc.subarray(PAN_OFFSET + PAN_LENGTH, DOB_OFFSET)) !== rest)) {
    throw unsupported('not a PAN Verification Record issued through DigiLocker by the Income Tax Department with status A');
  }
  const genderAt = indexOf(doc, encoder.encode(' gender="'), DOB_OFFSET);
  const uidAt = indexOf(doc, encoder.encode(' uid="'), genderAt + 1);
  const panAt = indexOf(doc, encoder.encode('<PAN num="'), uidAt + 1);
  if (genderAt < 0 || uidAt < 0 || panAt < 0 || panAt + 61 > Math.min(FIELD_WINDOW_BYTES, doc.length)) {
    throw unsupported(`gender, uid and the PAN must lie in the first ${FIELD_WINDOW_BYTES} bytes`);
  }
  const ascii = (from, length) => decoder.decode(doc.subarray(from, from + length));
  const values = {
    pan: ascii(PAN_OFFSET, PAN_LENGTH),
    dob: ascii(DOB_OFFSET, 10),
    gender: ascii(genderAt + 9, indexOf(doc, encoder.encode('"'), genderAt + 9) - genderAt - 9),
    uid: ascii(uidAt + 6, 32),
    verifiedOn: ascii(panAt + 34, 19),
  };
  if (strict) {
    if (!/^[0-9]{2}-[0-9]{2}-[0-9]{4}$/.test(values.dob) || doc[DOB_OFFSET + 10] !== 34) throw unsupported('the date of birth is not DD-MM-YYYY');
    if (!Object.hasOwn(GENDER_VALUES, values.gender)) throw unsupported('the gender is not MALE, FEMALE or TRANSGENDER');
    if (!/^[0-9a-f]{32}$/.test(values.uid) || ascii(uidAt + 38, 2) !== '">') throw unsupported('the uid is not 32 hex characters, last in its element');
    if (ascii(panAt + 10, PAN_LENGTH) !== values.pan) throw unsupported('the two PAN numbers differ');
    if (!/^[0-9]{2}-[0-9]{2}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}$/.test(values.verifiedOn) || ascii(panAt + 53, 8) !== '"></PAN>') {
      throw unsupported('the verification time is not DD-MM-YYYY HH:MM:SS');
    }
  }
  return { doc, signature, signer, hints: { genderAt, uidAt, panAt }, values };
}

// DD-MM-YYYY HH:MM:SS in IST as the circuit's verified_hour, YYYYMMDDHH.
export const verifiedHour = (verifiedOn) =>
  Number(`${verifiedOn.slice(6, 10)}${verifiedOn.slice(3, 5)}${verifiedOn.slice(0, 2)}${verifiedOn.slice(11, 13)}`);

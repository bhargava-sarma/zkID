// CredentialMatchProof input, built in the browser from the credential the
// server issued for the age proof (same signed bytes, signature and key).
// Mirrors backend/circuits/credential-match-proof/gen_input.js.
import { poseidon2 } from 'poseidon-lite/poseidon2';

export const NAME_MAX = 49;
export const GENDER_CODES = { M: 1, F: 2, O: 3 };

const NAME_KEY = '"name":"';

// A claimed name in the form the circuit hashes the signed one: the issuer has
// already trimmed and collapsed spaces, and the circuit lowercases A-Z.
export function normalizeName(name) {
  return name.trim().replace(/\s+/g, ' ').toLowerCase();
}

// Poseidon over the name bytes, 31 per field element, little-endian, zero-padded
// to 49 bytes: the same packing as the circuit.
export function nameHash(name) {
  const normalized = normalizeName(name);
  if (!/^[\x20-\x7E]*$/.test(normalized)) throw new Error('A claimed name must be printable ASCII.');
  if (normalized.length === 0 || normalized.length > NAME_MAX) {
    throw new Error(`A claimed name must be 1 to ${NAME_MAX} characters.`);
  }
  const pack = (from, to) => {
    let value = 0n;
    for (let i = to - 1; i >= from; i--) value = (value << 8n) + BigInt(i < normalized.length ? normalized.charCodeAt(i) : 0);
    return value;
  };
  return poseidon2([pack(0, 31), pack(31, NAME_MAX)]).toString();
}

// The name and gender as signed, read the way the circuit reads them.
export function signedFields(msg) {
  const text = String.fromCharCode(...msg);
  const start = text.indexOf(NAME_KEY) + NAME_KEY.length;
  const gender = text.match(/"gender":"(.)"/);
  if (start < NAME_KEY.length || !gender) throw new Error('The credential has no name or gender field.');
  return { name: text.substring(start, text.indexOf('"', start)), gender: gender[1] };
}

// issued: the age-proof input from /api/issue-credential. claims: { name?, gender? }.
export function buildMatchInput(issued, claims) {
  const signed = signedFields(issued.msg);
  return {
    msg: issued.msg,
    signature: issued.signature,
    modulus: issued.modulus,
    nameLength: signed.name.length,
    claimedNameHash: claims.name ? nameHash(claims.name) : '0',
    claimedGender: claims.gender ? GENDER_CODES[claims.gender] : 0,
  };
}

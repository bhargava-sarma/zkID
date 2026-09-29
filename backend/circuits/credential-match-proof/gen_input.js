#!/usr/bin/env node
// Builds input.json for CredentialMatchProof(119, 49) from a signed credential's
// circuit inputs (mock-issuer/circuit_inputs.json by default).
//
// Usage: node gen_input.js [--from <file>] [--out <file>] [--name <claimed>] [--gender M|F|O] [--tamper=<mode>]
// Tamper modes (negative controls):
//   signature  flip the low bit of signature limb 0
//   name       change one letter of the signed name, leaving the signature untouched

const fs = require('fs');
const path = require('path');
const { poseidon2 } = require('poseidon-lite/poseidon2');

const DEFAULT_SOURCE = path.join(__dirname, '..', '..', '..', 'mock-issuer', 'circuit_inputs.json');
const NAME_KEY = '"name":"';
const NAME_MAX = 49;
const GENDER_CODES = { M: 1, F: 2, O: 3 };
const TAMPER_MODES = ['signature', 'name'];

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

// A claimed name in the form the circuit hashes the signed one: the issuer has
// already trimmed and collapsed spaces, and the circuit lowercases A-Z.
function normalizeName(name) {
  return name.trim().replace(/\s+/g, ' ').toLowerCase();
}

// Poseidon over the name bytes, 31 per field element, little-endian, zero-padded
// to 49 bytes: the same packing as the circuit.
function nameHash(name) {
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
function signedFields(messageBytes) {
  const text = Buffer.from(messageBytes).toString('latin1');
  const start = text.indexOf(NAME_KEY) + NAME_KEY.length;
  const gender = text.match(/"gender":"(.)"/);
  if (start < NAME_KEY.length || !gender) throw new Error('The payload has no name or gender field.');
  const name = text.substring(start, text.indexOf('"', start));
  return { name, nameStart: start, gender: gender[1] };
}

// claims: { name, gender }; either may be omitted (0 in the circuit = not claimed).
function buildMatchInput(ci, claims = {}, tamper = null) {
  if (tamper && !TAMPER_MODES.includes(tamper)) {
    throw new Error(`--tamper must be one of: ${TAMPER_MODES.join(', ')}. Got "${tamper}".`);
  }
  if (claims.gender && !GENDER_CODES[claims.gender]) throw new Error('A claimed gender must be M, F or O.');

  const msg = [...ci.message_bytes];
  if (msg.length !== 119) throw new Error(`Expected a 119-byte payload, got ${msg.length}.`);
  const signed = signedFields(msg);

  const input = {
    msg,
    signature: [...ci.signature_limbs],
    modulus: [...ci.modulus_limbs],
    nameLength: signed.name.length,
    claimedNameHash: claims.name ? nameHash(claims.name) : '0',
    claimedGender: claims.gender ? GENDER_CODES[claims.gender] : 0,
  };

  if (tamper === 'signature') {
    input.signature[0] = (BigInt(input.signature[0]) ^ 1n).toString();
  } else if (tamper === 'name') {
    input.msg[signed.nameStart] = input.msg[signed.nameStart] === 88 ? 89 : 88; // 'X' or 'Y'
  }

  return { input, signed };
}

function main() {
  const sourcePath = arg('--from', DEFAULT_SOURCE);
  const claims = { name: arg('--name', null), gender: arg('--gender', null) };
  const tamperArg = process.argv.find((a) => a.startsWith('--tamper='));
  const tamper = tamperArg ? tamperArg.split('=')[1] : null;

  const ci = JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
  const { input, signed } = buildMatchInput(ci, claims, tamper);

  const outPath = path.join(__dirname, arg('--out', tamper ? `input_tampered_${tamper}.json` : 'input.json'));
  fs.writeFileSync(outPath, JSON.stringify(input, null, 2) + '\n');

  const tag = tamper ? `GEN/TAMPER:${tamper}` : 'GEN';
  console.log(`[${tag}] signed name    : ${signed.name} (${signed.name.length} bytes)`);
  console.log(`[${tag}] signed gender  : ${signed.gender}`);
  console.log(`[${tag}] claimed name   : ${claims.name ?? '(none)'} -> ${input.claimedNameHash}`);
  console.log(`[${tag}] claimed gender : ${claims.gender ?? '(none)'} -> ${input.claimedGender}`);
  console.log(`[${tag}] wrote ${path.basename(outPath)}`);
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(`[GEN] ERROR: ${err.message}`);
    process.exit(1);
  }
}

module.exports = { buildMatchInput, nameHash, normalizeName, signedFields, GENDER_CODES, NAME_MAX };

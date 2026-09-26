#!/usr/bin/env node
// Builds input.json for CredentialAgeProof(119) from mock-issuer/circuit_inputs.json.
//
// Usage: node gen_input.js [--from <file>] [--out <file>] [--threshold <YYYYMMDD>] [--tamper=<mode>]
// Tamper modes (negative controls):
//   signature  flip the low bit of signature limb 0
//   date       rewrite the signed DOB year, leaving the signature untouched
//   modulus    flip the low bit of modulus limb 0

const fs = require('fs');
const path = require('path');

const DEFAULT_SOURCE = path.join(__dirname, '..', '..', 'mock-issuer', 'circuit_inputs.json');
const PATTERN = '"dob":"';
const TAMPER_MODES = ['signature', 'date', 'modulus'];

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

function buildCircuitInput(ci, threshold, tamper = null) {
  if (tamper && !TAMPER_MODES.includes(tamper)) {
    throw new Error(`--tamper must be one of: ${TAMPER_MODES.join(', ')}. Got "${tamper}".`);
  }

  const msg = [...ci.message_bytes];
  if (msg.length !== 119) {
    throw new Error(`Expected a 119-byte payload, got ${msg.length}. Re-run sign_credential.js.`);
  }

  // Must agree with the circuit's own scan, which asserts exactly one match.
  const asText = Buffer.from(msg).toString('latin1');
  const dobIndex = asText.indexOf(PATTERN);
  if (dobIndex === -1) {
    throw new Error(`Pattern ${PATTERN} not found in the payload.`);
  }
  if (asText.indexOf(PATTERN, dobIndex + 1) !== -1) {
    throw new Error(`Pattern ${PATTERN} occurs more than once; the circuit asserts exactly one.`);
  }
  const dobValue = asText.substring(dobIndex + PATTERN.length, dobIndex + PATTERN.length + 10);

  const input = {
    msg,
    signature: [...ci.signature_limbs],
    modulus: [...ci.modulus_limbs],
    dobIndex,
    thresholdDate: threshold,
  };

  if (tamper === 'signature' || tamper === 'modulus') {
    input[tamper][0] = (BigInt(input[tamper][0]) ^ 1n).toString();
  } else if (tamper === 'date') {
    // "1998" -> "1888"
    const yearAt = dobIndex + PATTERN.length;
    input.msg[yearAt + 1] = '8'.charCodeAt(0);
    input.msg[yearAt + 2] = '8'.charCodeAt(0);
  }

  return { input, dobIndex, dobValue };
}

function main() {
  const sourcePath = arg('--from', DEFAULT_SOURCE);
  const threshold = parseInt(arg('--threshold', '20080807'), 10);
  const tamperArg = process.argv.find((a) => a.startsWith('--tamper='));
  const tamper = tamperArg ? tamperArg.split('=')[1] : null;

  const ci = JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
  const { input, dobIndex, dobValue } = buildCircuitInput(ci, threshold, tamper);

  const outPath = path.join(__dirname, arg('--out', tamper ? `input_tampered_${tamper}.json` : 'input.json'));
  fs.writeFileSync(outPath, JSON.stringify(input, null, 2) + '\n');

  const tag = tamper ? `GEN/TAMPER:${tamper}` : 'GEN';
  console.log(`[${tag}] source        : ${path.relative(process.cwd(), sourcePath)}`);
  console.log(`[${tag}] payload       : ${input.msg.length} bytes (${ci.padding.canonical_byte_length} canonical + ${ci.padding.pad_byte_count} pad)`);
  console.log(`[${tag}] dobIndex      : ${dobIndex}  (found by scanning, not hardcoded)`);
  console.log(`[${tag}] dob value     : ${dobValue}`);
  console.log(`[${tag}] thresholdDate : ${threshold}`);
  if (tamper === 'date') {
    const at = dobIndex + PATTERN.length;
    const after = Buffer.from(input.msg).toString('latin1').substring(at, at + 10);
    console.log(`[${tag}] msg date now  : ${after}  (signature NOT updated)`);
  } else if (tamper) {
    console.log(`[${tag}] TAMPERED      : flipped low bit of ${tamper} limb 0`);
  }
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

module.exports = { buildCircuitInput };

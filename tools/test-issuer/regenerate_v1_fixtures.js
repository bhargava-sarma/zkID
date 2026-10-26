#!/usr/bin/env node
// Regenerates the v1 proof fixtures (Hardhat policy tests) under a fresh TEST
// key. The key lives only in this process's memory and
// is discarded on exit, so nobody can sign anything else under it.
//
// Needs the v1 circuit artifacts: cd backend && npm run fetch-circuit
// Usage: node tools/test-issuer/regenerate_v1_fixtures.js

const fs = require('fs');
const path = require('path');
const { generateTestKeys, modulusHex } = require('./keys');
const { signPayload } = require('./sign_credential');

const ROOT = path.join(__dirname, '..', '..');
const BACKEND = path.join(ROOT, 'backend');
const snarkjs = require(require.resolve('snarkjs', { paths: [BACKEND] }));
const { buildCircuitInput } = require(path.join(BACKEND, 'circuits/credential-age-proof/gen_input'));
const { buildMatchInput } = require(path.join(BACKEND, 'circuits/credential-match-proof/gen_input'));

// 18 years before 2026-09-28: the date the Hardhat tests expect.
const CUTOFF = 20080928;
const PAYLOAD = require('./synthetic-payload.json');

const CAP = path.join(BACKEND, 'circuits/credential-age-proof');
const CMP = path.join(BACKEND, 'circuits/credential-match-proof');
const CIRCUITS = {
  age: {
    wasm: path.join(CAP, 'credential_age_proof_js/credential_age_proof.wasm'),
    zkey: path.join(CAP, 'cap_final.zkey'),
    vkey: path.join(CAP, 'verification_key.json'),
  },
  match: {
    wasm: path.join(CMP, 'credential_match_proof_js/credential_match_proof.wasm'),
    zkey: path.join(CMP, 'cmp_final.zkey'),
    vkey: path.join(CMP, 'match_verification_key.json'),
  },
};

const HARDHAT_FIXTURES = path.join(BACKEND, 'hardhat-deploy/test/fixtures');

const NOTE =
  'SYNTHETIC TEST FIXTURE. Honest proof of tools/test-issuer/synthetic-payload.json (Test User One, DOB 1998-04-12, M), ' +
  'signed with a test key that existed only in memory while tools/test-issuer/regenerate_v1_fixtures.js ran. ' +
  'Never trust its issuer key outside tests.';

async function prove(kind, input) {
  const { wasm, zkey, vkey } = CIRCUITS[kind];
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
  if (!(await snarkjs.groth16.verify(JSON.parse(fs.readFileSync(vkey, 'utf8')), publicSignals, proof))) {
    throw new Error(`${kind} proof did not verify`);
  }
  return { proof, publicSignals };
}

const write = (file, value) => {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
  console.log(`wrote ${path.relative(ROOT, file)}`);
};

async function main() {
  for (const { wasm, zkey, vkey } of Object.values(CIRCUITS)) {
    for (const p of [wasm, zkey, vkey]) {
      if (!fs.existsSync(p)) throw new Error(`Missing ${path.relative(ROOT, p)}. Run: cd backend && npm run fetch-circuit`);
    }
  }

  const keys = generateTestKeys();
  const { circuitInputs } = signPayload(PAYLOAD, keys);
  const issuer = { modulus_hex: modulusHex(keys.publicKey), modulus_limbs: circuitInputs.modulus_limbs };

  const age = await prove('age', buildCircuitInput(circuitInputs, CUTOFF).input);
  const name = await prove('match', buildMatchInput(circuitInputs, { name: PAYLOAD.name }).input);
  const gender = await prove('match', buildMatchInput(circuitInputs, { gender: PAYLOAD.gender }).input);
  const none = await prove('match', buildMatchInput(circuitInputs, {}).input);

  write(path.join(HARDHAT_FIXTURES, 'test-issuer.json'), { note: `${NOTE} This file holds that key's public half.`, ...issuer });
  write(path.join(HARDHAT_FIXTURES, 'age.json'), { note: `${NOTE} Age proof at cutoff ${CUTOFF}.`, ...age });
  write(path.join(HARDHAT_FIXTURES, 'match-name.json'), { note: `${NOTE} Name claim "${PAYLOAD.name}".`, ...name });
  write(path.join(HARDHAT_FIXTURES, 'match-gender.json'), { note: `${NOTE} Gender claim ${PAYLOAD.gender}.`, ...gender });
  write(path.join(HARDHAT_FIXTURES, 'match-none.json'), { note: `${NOTE} No claims (the policy must reject it).`, ...none });
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(`[FIXTURES] ${err.message}`);
    process.exit(1);
  });

#!/usr/bin/env node
// Baseline on the same machine: zkID v1's CredentialAgeProof (256,574
// constraints) in Node, on a synthetic credential under an ephemeral test key.
// Needs: cd backend && npm run fetch-circuit

import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

const require = createRequire(import.meta.url);
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const { signPayload } = require(path.join(root, 'tools/test-issuer/sign_credential.js'));
const { generateTestKeys } = require(path.join(root, 'tools/test-issuer/keys.js'));
const { buildCircuitInput } = require(path.join(root, 'backend/circuits/credential-age-proof/gen_input.js'));
const CAP = path.join(root, 'backend/circuits/credential-age-proof');

const { circuitInputs } = signPayload(require(path.join(root, 'tools/test-issuer/synthetic-payload.json')), generateTestKeys());
const input = buildCircuitInput(circuitInputs, 20080928).input;
const runs = [];
for (let i = 0; i < 3; i++) {
  const t0 = performance.now();
  const wtns = { type: 'mem' };
  await snarkjs.wtns.calculate(input, path.join(CAP, 'credential_age_proof_js/credential_age_proof.wasm'), wtns);
  const t1 = performance.now();
  await snarkjs.groth16.prove(path.join(CAP, 'cap_final.zkey'), wtns);
  runs.push({ witnessMs: Math.round(t1 - t0), proveMs: Math.round(performance.now() - t1) });
  console.log(JSON.stringify(runs.at(-1)));
}
const median = (xs) => [...xs].sort((a, b) => a - b)[1];
const summary = { circuit: 'zkID v1 CredentialAgeProof(119)', runs, medianWitnessMs: median(runs.map((r) => r.witnessMs)), medianProveMs: median(runs.map((r) => r.proveMs)), peakRssMB: Math.round(process.resourceUsage().maxRSS / 1024) };
fs.writeFileSync(new URL('./results/prove_node_v1.json', import.meta.url), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify(summary));
await globalThis.curve_bn128?.terminate();

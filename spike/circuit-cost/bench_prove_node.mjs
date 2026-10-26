#!/usr/bin/env node
// Proving cost of Anon Aadhaar's published v2.0.0 circuit in Node (snarkjs),
// on synthetic V2 QR data. Witness and proof are timed separately; peak RSS is
// the whole process's.
//
// Usage: AA_ARTIFACTS=<dir with aadhaar-verifier.wasm, circuit_final.zkey,
//        vkey.json> node bench_prove_node.mjs [runs]

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as snarkjs from 'snarkjs';
import { syntheticInput } from './aa_input.mjs';

const dir = process.env.AA_ARTIFACTS;
if (!dir) throw new Error('Set AA_ARTIFACTS to the directory holding the Anon Aadhaar v2.0.0 artifacts.');
const wasm = path.join(dir, 'aadhaar-verifier.wasm');
const zkey = path.join(dir, 'circuit_final.zkey');
const vkey = JSON.parse(fs.readFileSync(path.join(dir, 'vkey.json'), 'utf8'));
const runs = Number(process.argv[2] ?? 3);

const results = [];
for (let i = 0; i < runs; i++) {
  const { input, signedBytes } = syntheticInput();
  const t0 = performance.now();
  const wtns = { type: 'mem' };
  await snarkjs.wtns.calculate(input, wasm, wtns);
  const t1 = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns);
  const t2 = performance.now();
  const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  const t3 = performance.now();
  if (!valid) throw new Error('Proof did not verify.');
  results.push({ signedBytes, witnessMs: Math.round(t1 - t0), proveMs: Math.round(t2 - t1), verifyMs: Math.round(t3 - t2), publicSignals: publicSignals.length });
  console.log(JSON.stringify(results.at(-1)));
}

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const summary = {
  when: new Date().toISOString(),
  machine: { cpu: os.cpus()[0].model, cores: os.cpus().length, memGB: Math.round(os.totalmem() / 2 ** 30), node: process.version },
  snarkjs: JSON.parse(fs.readFileSync(new URL("./node_modules/snarkjs/package.json", import.meta.url), "utf8")).version,
  runs: results,
  medianWitnessMs: median(results.map((r) => r.witnessMs)),
  medianProveMs: median(results.map((r) => r.proveMs)),
  peakRssMB: Math.round(process.resourceUsage().maxRSS / 1024),
};
fs.mkdirSync(new URL('./results/', import.meta.url), { recursive: true });
fs.writeFileSync(new URL('./results/prove_node.json', import.meta.url), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify({ medianWitnessMs: summary.medianWitnessMs, medianProveMs: summary.medianProveMs, peakRssMB: summary.peakRssMB }));
await globalThis.curve_bn128?.terminate();

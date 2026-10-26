#!/usr/bin/env node
// Proving cost in Node, through this package (pinned artifacts), on synthetic
// V5 codes. Witness and proof are timed separately; peak RSS is the process's.
//
// Usage: node bench/node.mjs [runs]   (AA_ARTIFACTS=<dir> to use artifacts elsewhere)

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { DEFAULT_DIR, buildInput, checkedArtifact, close, verify } from '../index.mjs';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../../secure-qr/synthetic.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = process.env.AA_ARTIFACTS || DEFAULT_DIR;
const runs = Number(process.argv[2] ?? 3);
const wasm = await checkedArtifact('aadhaar-verifier.wasm', dir);
const zkey = await checkedArtifact('circuit_final.zkey', dir);

const results = [];
for (let i = 0; i < runs; i++) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const { text } = makeSyntheticSecureQr(privateKey, {
    version: 'V5',
    photo: syntheticPhoto(900),
    trailing: unknownTrailer(27),
    fields: syntheticFields(),
  });
  const input = buildInput(text, publicKey, { nullifierSeed: 1n, signalHash: 1n });
  const t0 = performance.now();
  const wtns = { type: 'mem' };
  await snarkjs.wtns.calculate(input, wasm, wtns);
  const t1 = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns);
  const t2 = performance.now();
  if (!(await verify(proof, publicSignals, { dir }))) throw new Error('Proof did not verify.');
  const t3 = performance.now();
  results.push({ witnessMs: Math.round(t1 - t0), proveMs: Math.round(t2 - t1), verifyMs: Math.round(t3 - t2) });
  console.log(JSON.stringify(results.at(-1)));
}

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const summary = {
  when: new Date().toISOString(),
  machine: { cpu: os.cpus()[0].model, cores: os.cpus().length, memGB: Math.round(os.totalmem() / 2 ** 30), node: process.version },
  snarkjs: JSON.parse(fs.readFileSync(path.join(here, '..', 'node_modules', 'snarkjs', 'package.json'), 'utf8')).version,
  runs: results,
  medianWitnessMs: median(results.map((r) => r.witnessMs)),
  medianProveMs: median(results.map((r) => r.proveMs)),
  peakRssMB: Math.round(process.resourceUsage().maxRSS / 1024),
};
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
fs.writeFileSync(path.join(here, 'results', 'node.json'), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify({ medianWitnessMs: summary.medianWitnessMs, medianProveMs: summary.medianProveMs, peakRssMB: summary.peakRssMB }));
await close();

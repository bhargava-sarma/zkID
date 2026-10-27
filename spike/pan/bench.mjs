#!/usr/bin/env node
// Times a proof for a SYNTHETIC PAN record with the dev key (build.mjs), in
// Node: witness, then Groth16 proving, with all threads or one (--single).
// Prints time and peak memory. Usage: node --max-old-space-size=14000 bench.mjs [--single]

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { makeRecord, testIssuer } from './synthetic.mjs';
import { circuitInput, readRecord } from './record.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const build = path.join(here, 'build');
const wasm = path.join(build, 'pan-verifier_js', 'pan-verifier.wasm');
const zkey = path.join(build, 'pan-verifier.dev.zkey');
const singleThread = process.argv.includes('--single');

const record = readRecord(await makeRecord(testIssuer(), { dob: '15-06-2000', gender: 'FEMALE' }));
const input = circuitInput(record, { dobCutoff: 20071027, nullifierSeed: 1111n, signalHash: 2222n, revealGender: true });

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkid-pan-bench-'));
const wtns = path.join(dir, 'w.wtns');
let t = performance.now();
await snarkjs.wtns.calculate(input, wasm, wtns);
const witnessSeconds = (performance.now() - t) / 1000;
t = performance.now();
const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns, undefined, { singleThread });
const proveSeconds = (performance.now() - t) / 1000;
t = performance.now();
const valid = await snarkjs.groth16.verify(JSON.parse(fs.readFileSync(path.join(build, 'vkey.json'), 'utf8')), publicSignals, proof);
const verifyMs = performance.now() - t;
fs.rmSync(dir, { recursive: true, force: true });

console.log(JSON.stringify({
  threads: singleThread ? 1 : os.cpus().length,
  cpu: os.cpus()[0].model,
  witnessSeconds: +witnessSeconds.toFixed(1),
  proveSeconds: +proveSeconds.toFixed(1),
  peakMemoryGB: +(process.resourceUsage().maxRSS / 1e6).toFixed(2),
  zkeyMB: Math.round(fs.statSync(zkey).size / 1e6),
  verifyMs: Math.round(verifyMs),
  valid,
}));
await globalThis.curve_bn128?.terminate();

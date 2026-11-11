#!/usr/bin/env node
// Times a proof for a SYNTHETIC PAN record with Barretenberg (UltraHonk) in
// Node, on its WASM backend (what a browser runs), and samples the process's
// memory. Usage: node bench.mjs [--single]

import os from 'node:os';
import zlib from 'node:zlib';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { makeRecord, testIssuer } from '../pan/synthetic.mjs';
import { readRecord } from '../pan/record.mjs';
import { program } from './circuit.mjs';
import { noirInput } from './inputs.mjs';

const threads = process.argv.includes('--single') ? 1 : os.cpus().length;
const compiled = await program();
const record = readRecord(await makeRecord(testIssuer(), { dob: '15-06-2000', gender: 'FEMALE' }));
const input = noirInput(record, { dobCutoff: 20071027, nullifierSeed: 1111n, signalHash: 2222n, revealGender: true });

let peak = 0;
const sampler = setInterval(() => (peak = Math.max(peak, process.memoryUsage().rss)), 200);
const seconds = (start) => +((performance.now() - start) / 1000).toFixed(1);

let t = performance.now();
const { witness } = await new Noir(compiled).execute(input);
const execute = seconds(t);

const api = await Barretenberg.new({ threads, backend: BackendType.WasmWorker });
const [gates] = await api.acirGetCircuitSizes(zlib.gunzipSync(Buffer.from(compiled.bytecode, 'base64')), false, true);
const backend = new UltraHonkBackend(compiled.bytecode, api);
t = performance.now();
const proof = await backend.generateProof(witness);
const prove = seconds(t);
t = performance.now();
const valid = await backend.verifyProof(proof);
const verify = seconds(t);
clearInterval(sampler);
await api.destroy();

console.log(JSON.stringify({ threads, gates, valid, executeSeconds: execute, proveSeconds: prove, verifySeconds: verify, proofBytes: proof.proof.length, peakMemoryGB: +(peak / 1e9).toFixed(2) }));

#!/usr/bin/env node
// Builds the PAN prototype into build/ (gitignored): the circuit (r1cs, wasm),
// Hermez's 2^21 powers of tau (downloaded once, checked by BLAKE2b), and a
// Groth16 proving key with NO phase-2 contribution. That key is for measuring
// cost only: whoever runs this setup could forge proofs with it.
//
// Usage: node --max-old-space-size=14000 build.mjs   (the setup needs about 12 GB)

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const build = path.join(here, 'build');
const r1cs = path.join(build, 'pan-verifier.r1cs');
const ptau = path.join(build, 'pot21.ptau');
const zkey = path.join(build, 'pan-verifier.dev.zkey');
const PTAU_URL = 'https://circom.info/powersOfTau28_hez_final_21.ptau';
// From snarkjs's README, as packages/circuit/setup/verify-setup.sh pins the 2^20 file.
const PTAU_B2 = '9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678';

const step = (text) => console.log(`[pan build] ${text}`);
const newer = (out, ...inputs) => fs.existsSync(out) && inputs.every((i) => fs.statSync(i).mtimeMs <= fs.statSync(out).mtimeMs);
fs.mkdirSync(build, { recursive: true });

step('constants');
execFileSync(process.execPath, [path.join(here, 'gen-constants.mjs'), '--check'], { stdio: 'inherit' });

const sources = fs.readdirSync(path.join(here, 'circuits')).map((f) => path.join(here, 'circuits', f));
if (!newer(r1cs, ...sources)) {
  step('compiling (about 2 minutes, 6 GB)');
  execFileSync('circom', [path.join(here, 'circuits', 'pan-verifier.circom'), '--r1cs', '--wasm', '--O2', '-l', path.join(here, 'node_modules'), '-o', build], { stdio: 'inherit' });
}
const info = await snarkjs.r1cs.info(r1cs);
step(`${info.nConstraints} constraints, ${info.nVars} wires, ${info.nPubInputs} public inputs, ${info.nOutputs} outputs`);

if (!fs.existsSync(ptau)) {
  step(`downloading ${PTAU_URL} (2.4 GB)`);
  execFileSync('curl', ['-sSfL', '-o', ptau, PTAU_URL], { stdio: 'inherit' });
}
step('checking the powers of tau');
const b2 = crypto.createHash('blake2b512');
for await (const chunk of fs.createReadStream(ptau, { highWaterMark: 1 << 24 })) b2.update(chunk);
if (b2.digest('hex') !== PTAU_B2) throw new Error(`${ptau} is not Hermez's 2^21 powers of tau`);

if (!newer(zkey, r1cs, ptau)) {
  step('Groth16 setup, DEV KEY WITHOUT CONTRIBUTIONS (tens of minutes)');
  await snarkjs.zKey.newZKey(r1cs, ptau, zkey, { info: (m) => /setup|Circuit/i.test(m) && step(m), debug() {}, warn: console.warn, error: console.error });
}
const vkey = await snarkjs.zKey.exportVerificationKey(zkey);
fs.writeFileSync(path.join(build, 'vkey.json'), JSON.stringify(vkey));
step(`done: ${path.relative(here, zkey)} (${(fs.statSync(zkey).size / 1e6).toFixed(0)} MB), build/vkey.json`);
await globalThis.curve_bn128?.terminate();

#!/usr/bin/env node
// Builds the pinned circuit artifacts from circuit/:
//   artifacts/pan_verifier.json  the program noir_wasm compiles (version, hash,
//                                ABI and bytecode; no debug information)
//   artifacts/vk.json            its UltraHonk verification key, from bb.js
// The holder app proves with the first and the verifier SDK checks proofs with
// the second, pinned by SHA-256. With --check, rebuilds both and fails if they
// differ from the committed files (CI runs this).
// Usage: node build.mjs [--check]

import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import { compile, createFileManager } from '@noir-lang/noir_wasm';

const PROGRAM = new URL('./artifacts/pan_verifier.json', import.meta.url);
const VK = new URL('./artifacts/vk.json', import.meta.url);
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const version = (name) => JSON.parse(fs.readFileSync(new URL(`./node_modules/${name}/package.json`, import.meta.url), 'utf8')).version;

const quiet = { log: console.log, info: console.info, debug: console.debug };
console.log = console.info = console.debug = () => {}; // noir_wasm narrates every file it reads
const { program } = await compile(createFileManager(fileURLToPath(new URL('./circuit', import.meta.url))));
Object.assign(console, quiet);
const programText = `${JSON.stringify({ noir_version: program.noir_version, hash: program.hash, abi: program.abi, bytecode: program.bytecode })}\n`;

const api = await Barretenberg.new({ threads: 1 });
const vk = await new UltraHonkBackend(program.bytecode, api).getVerificationKey();
await api.destroy();
const vkText = `${JSON.stringify(
  { bbVersion: version('@aztec/bb.js'), noirVersion: program.noir_version, programSha256: sha256(programText), vkSha256: sha256(vk), vk: Buffer.from(vk).toString('base64') },
  null,
  2,
)}\n`;

if (process.argv.includes('--check')) {
  const stale = [
    [PROGRAM, programText],
    [VK, vkText],
  ].filter(([file, text]) => !fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== text);
  if (stale.length) {
    console.error(`stale: ${stale.map(([file]) => fileURLToPath(file)).join(', ')}. Run node build.mjs and commit the result.`);
    process.exit(1);
  }
  console.log('artifacts/pan_verifier.json and artifacts/vk.json match circuit/');
} else {
  fs.writeFileSync(PROGRAM, programText);
  fs.writeFileSync(VK, vkText);
  console.log(`wrote artifacts/pan_verifier.json (${programText.length} bytes, SHA-256 ${sha256(programText).slice(0, 16)}…) and artifacts/vk.json (${vk.length}-byte key)`);
}

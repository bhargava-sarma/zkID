#!/usr/bin/env node
// Writes frontend/public/bench/bench-synthetic.json for the phone benchmark page: a
// SYNTHETIC circuit input (a V5-shaped QR signed with an ephemeral key, no real
// data), the artifact hashes from artifacts.json, and the verification key.
//
// Usage: node bench/make-phone-bench.mjs   (needs artifacts/vkey.json: npm run fetch vkey.json)

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_DIR, MANIFEST, buildInput, checkedArtifact } from '../index.mjs';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../../secure-qr/synthetic.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, '..', '..', '..', 'frontend', 'public', 'bench', 'bench-synthetic.json');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const { text } = makeSyntheticSecureQr(privateKey, {
  version: 'V5',
  photo: syntheticPhoto(900),
  trailing: unknownTrailer(27),
  fields: syntheticFields({ generatedAt: new Date() }),
});
const wasm = MANIFEST.files.find((f) => f.name === 'aadhaar-verifier.wasm');
const zkey = MANIFEST.files.find((f) => f.name === 'circuit_final.zkey');
const vkey = JSON.parse(fs.readFileSync(await checkedArtifact('vkey.json', process.env.AA_ARTIFACTS || DEFAULT_DIR), 'utf8'));

const bench = {
  note: 'SYNTHETIC benchmark input: a V5-shaped Secure QR signed with an ephemeral test key. No real data.',
  generated: new Date().toISOString(),
  release: MANIFEST.release,
  wasm: { name: wasm.name, bytes: wasm.bytes, sha256: wasm.sha256 },
  zkey: { bytes: zkey.bytes, sha256: zkey.sha256, path: MANIFEST.chunkedZkey.path, chunks: MANIFEST.chunkedZkey.files },
  input: buildInput(text, publicKey, { nullifierSeed: 1n, signalHash: 1n }),
  vkey,
};
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(bench) + '\n');
console.log(`wrote ${path.relative(process.cwd(), out)} (${(fs.statSync(out).size / 1024).toFixed(0)} KB)`);

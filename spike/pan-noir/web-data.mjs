#!/usr/bin/env node
// Writes what the browser test page loads into build/web-public/ (Vite's public
// directory): the compiled circuit, the input for a SYNTHETIC record, the
// verification key, and the service worker. Usage: node web-data.mjs

import fs from 'node:fs';
import path from 'node:path';
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import { makeRecord, testIssuer } from '../pan/synthetic.mjs';
import { readRecord } from '../pan/record.mjs';
import { BUILD, HERE, program } from './circuit.mjs';
import { noirInput } from './inputs.mjs';

const out = path.join(BUILD, 'web-public');
fs.mkdirSync(out, { recursive: true });

const compiled = await program();
const record = readRecord(await makeRecord(testIssuer(), { dob: '15-06-2000', gender: 'FEMALE' }));
const input = noirInput(record, { dobCutoff: 20071027, nullifierSeed: 1111n, signalHash: 2222n, revealGender: true });
const api = await Barretenberg.new({ threads: 1 });
const vk = await new UltraHonkBackend(compiled.bytecode, api).getVerificationKey();
await api.destroy();

fs.writeFileSync(path.join(out, 'program.json'), JSON.stringify(compiled));
fs.writeFileSync(path.join(out, 'input.json'), JSON.stringify(input));
fs.writeFileSync(path.join(out, 'vk.bin'), vk);
fs.copyFileSync(path.join(HERE, 'web', 'coi-sw.js'), path.join(out, 'coi-sw.js'));

// The page bundles these packages; their licenses travel with it.
const BUNDLED = ['@aztec/bb.js', '@noir-lang/noir_js', '@noir-lang/acvm_js', '@noir-lang/noirc_abi', '@noir-lang/types', 'pako', 'comlink', 'msgpackr', 'idb-keyval', 'tslib'];
const notices = BUNDLED.map((name) => {
  const dir = path.join(HERE, 'node_modules', name);
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  const file = fs.readdirSync(dir).find((f) => /^(licen[cs]e|copying)/i.test(f));
  const source = typeof pkg.repository === 'string' ? pkg.repository : pkg.repository?.url;
  return [`${pkg.name} ${pkg.version}: ${pkg.license}${source ? ` (${source})` : ''}`, file ? fs.readFileSync(path.join(dir, file), 'utf8').trim() : '(no license file in the package; see its source)'].join('\n\n');
});
fs.writeFileSync(path.join(out, 'THIRD_PARTY_LICENSES.txt'), `${notices.join(`\n\n${'-'.repeat(72)}\n\n`)}\n`);
console.log(`wrote ${path.relative(HERE, out)}: program.json, input.json (synthetic record), vk.bin (${vk.length} bytes), coi-sw.js, THIRD_PARTY_LICENSES.txt`);

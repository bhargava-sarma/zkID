#!/usr/bin/env node
// Builds the hosted demo for Vercel, in Build Output API v3 form, into
// apps/demo-rp/.vercel/output:
//   static/holder/          the holder app's demo build: trusts UIDAI's keys and this build's TEST key
//   functions/index.func/   the demo shops (vercel/handler.ts), compiled to JavaScript in the
//                           repository's layout, with every file and package it loads
//   config.json             /holder/ is static; everything else goes to the function
// Each build makes a new TEST issuer key. Its private half is written only into
// the function, which signs the shops' sample QRs with it.
//
// Vercel runs this as the build command (apps/demo-rp/vercel.json). Locally:
// node vercel/build.mjs, then node vercel/serve-output.mjs to try the output.

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { nodeFileTrace } from '@vercel/nft';

const app = path.join(path.dirname(fileURLToPath(import.meta.url)), '..'); // apps/demo-rp
const root = path.join(app, '..', '..');
const frontend = path.join(root, 'frontend');
const build = path.join(app, '.build');
const output = path.join(app, '.vercel', 'output');
const func = path.join(output, 'functions', 'index.func');
const HANDLER = 'apps/demo-rp/vercel/handler.js'; // in .build

const step = (text) => console.log(`[demo build] ${text}`);
const writeJson = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
};

fs.rmSync(build, { recursive: true, force: true });
fs.rmSync(output, { recursive: true, force: true });

step('compiling the shops and the packages they import');
execFileSync(process.execPath, [path.join(app, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', path.join(app, 'vercel', 'tsconfig.build.json')], { stdio: 'inherit' });
writeJson(path.join(build, 'package.json'), { type: 'module' });
// The data files the packages read at run time, next to the compiled code.
for (const file of ['packages/verifier-sdk/vkey.json', 'packages/issuer-registry/registry.json', 'security/compromised-keys.json']) {
  fs.mkdirSync(path.dirname(path.join(build, file)), { recursive: true });
  fs.copyFileSync(path.join(root, file), path.join(build, file));
}

step('making the TEST issuer key');
const { keyHashFromModulus } = await import(pathToFileURL(path.join(build, 'packages/circuit/input.mjs')).href);
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const modulus = Buffer.from(publicKey.export({ format: 'jwk' }).n, 'base64url').toString('hex');
const note = `TEST issuer for the hosted zkID demo, made by vercel/build.mjs on ${new Date().toISOString()}: NOT UIDAI. Only this deployment's demo shops and holder demo build trust it.`;
const keys = [{ id: 'zkid-demo-test-key', label: 'TEST ISSUER (zkID demo, not UIDAI)', modulus, keyHash: keyHashFromModulus(BigInt(`0x${modulus}`)), notBefore: 0, notAfter: 2 ** 32 }];
const publicFile = path.join(build, 'demo-issuer.public.json');
writeJson(publicFile, { note, keys });
writeJson(path.join(build, 'apps/demo-rp/vercel/demo-issuer.json'), { note, keys, privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) });

step('building the holder app (demo build, under /holder/)');
if (!fs.existsSync(path.join(frontend, 'node_modules', 'vite'))) {
  execFileSync('npm', ['ci', '--no-audit', '--no-fund'], { cwd: frontend, stdio: 'inherit' });
}
const holderOut = path.join(output, 'static', 'holder');
execFileSync(path.join(frontend, 'node_modules', '.bin', 'vite'), ['build', '--mode', 'demo', '--base', '/holder/', '--outDir', holderOut, '--emptyOutDir'], {
  cwd: frontend,
  stdio: 'inherit',
  env: { ...process.env, ZKID_DEMO_ISSUER_FILE: publicFile },
});
fs.rmSync(path.join(holderOut, 'bench'), { recursive: true, force: true }); // the phone benchmark page is not part of the demo

step('collecting the function');
const { fileList, warnings } = await nodeFileTrace([path.join(build, HANDLER)], { base: app });
for (const warning of warnings) {
  if (!/Failed to resolve dependency "(web-worker|worker_threads)"/.test(String(warning.message))) console.warn(`[demo build] nft: ${warning.message}`);
}
const files = new Set(fileList);
// Read with fs at run time: make sure they are there whatever the tracer saw.
for (const file of ['packages/verifier-sdk/vkey.json', 'packages/issuer-registry/registry.json', 'security/compromised-keys.json', 'apps/demo-rp/vercel/demo-issuer.json', 'package.json']) {
  files.add(path.join('.build', file));
}
for (const file of files) {
  if (file.startsWith('..')) throw new Error(`The function needs ${file}, outside apps/demo-rp.`);
  const target = path.join(func, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.cpSync(path.join(app, file), target, { dereference: true });
}
writeJson(path.join(func, '.vc-config.json'), { runtime: 'nodejs22.x', handler: path.join('.build', HANDLER), launcherType: 'Nodejs', shouldAddHelpers: false });

writeJson(path.join(output, 'config.json'), {
  version: 3,
  routes: [{ src: '^/holder/?$', dest: '/holder/index.html' }, { handle: 'filesystem' }, { src: '^/(.*)$', dest: '/index' }],
});

const size = [...files].reduce((sum, file) => sum + fs.statSync(path.join(app, file)).size, 0);
step(`done: ${files.size} files in the function (${(size / 1e6).toFixed(1)} MB), holder app in static/holder`);

#!/usr/bin/env node
// Times a proof for a SYNTHETIC PAN record in headless Chromium, as the holder
// app would make it: snarkjs's browser build, the wasm and the dev key fetched
// into memory, then fullProve. Samples the browser's total memory meanwhile.
// Usage: node browser-bench.mjs [--single]   (needs npm run build, and
// Playwright's Chromium, as apps/demo-rp's end-to-end test does)

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeRecord, testIssuer } from './synthetic.mjs';
import { circuitInput, readRecord } from './record.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const build = path.join(here, 'build');
const single = process.argv.includes('--single');
const playwright = await import(process.env.PLAYWRIGHT || path.join(here, '..', '..', 'apps', 'demo-rp', 'node_modules', 'playwright', 'index.mjs'));

const record = readRecord(await makeRecord(testIssuer(), { dob: '15-06-2000', gender: 'FEMALE' }));
const input = JSON.stringify(circuitInput(record, { dobCutoff: 20071027, nullifierSeed: 1111n, signalHash: 2222n, revealGender: true }));

const page = `<!doctype html><meta charset="utf-8"><script src="/snarkjs.min.js"></script><script>
(async () => {
  const get = (url) => fetch(url).then((r) => r.arrayBuffer()).then((b) => new Uint8Array(b));
  const [input, wasm, zkey, vkey] = await Promise.all([fetch('/input.json').then((r) => r.json()), get('/pan-verifier.wasm'), get('/pan-verifier.dev.zkey'), fetch('/vkey.json').then((r) => r.json())]);
  window.loaded = true;
  const started = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, { type: 'mem', data: wasm }, { type: 'mem', data: zkey }, undefined, undefined, { singleThread: ${single} });
  const seconds = (performance.now() - started) / 1000;
  window.result = { seconds, valid: await snarkjs.groth16.verify(vkey, publicSignals, proof) };
})().catch((e) => { window.result = { error: String(e && e.message || e) }; });
</script>`;
const files = {
  '/snarkjs.min.js': path.join(here, 'node_modules', 'snarkjs', 'build', 'snarkjs.min.js'),
  '/pan-verifier.wasm': path.join(build, 'pan-verifier_js', 'pan-verifier.wasm'),
  '/pan-verifier.dev.zkey': path.join(build, 'pan-verifier.dev.zkey'),
  '/vkey.json': path.join(build, 'vkey.json'),
};
const server = http.createServer((req, res) => {
  if (req.url === '/') return res.writeHead(200, { 'content-type': 'text/html' }).end(page);
  if (req.url === '/input.json') return res.writeHead(200, { 'content-type': 'application/json' }).end(input);
  const file = files[req.url];
  if (!file) return res.writeHead(404).end();
  res.writeHead(200, { 'content-type': req.url.endsWith('.js') ? 'text/javascript' : 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(4400, r));

// The browser's processes' total resident memory, sampled.
let peak = 0;
const rss = () => {
  try {
    return execFileSync('ps', ['-o', 'rss=', '-C', 'chrome,headless_shell,chromium'], { encoding: 'utf8' }).split('\n').filter(Boolean).reduce((a, b) => a + Number(b), 0) * 1024;
  } catch {
    return 0;
  }
};
const sampler = setInterval(() => (peak = Math.max(peak, rss())), 500);

const browser = await (playwright.chromium ?? playwright.default.chromium).launch();
const tab = await browser.newPage();
await tab.goto('http://localhost:4400/');
await tab.waitForFunction(() => window.result, null, { timeout: 30 * 60 * 1000, polling: 1000 });
const result = await tab.evaluate(() => window.result);
clearInterval(sampler);
await browser.close();
server.close();
console.log(JSON.stringify({ threads: single ? 1 : 'all', ...result, seconds: result.seconds && +result.seconds.toFixed(1), peakBrowserMemoryGB: +(peak / 1e9).toFixed(2) }));

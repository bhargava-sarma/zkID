#!/usr/bin/env node
// Proving cost of Anon Aadhaar's published v2.0.0 circuit in headless Chromium
// (snarkjs browser build, local HTTP server), on synthetic V2 QR data. Peak
// memory is sampled from the browser's processes while proving.
//
// Usage: AA_ARTIFACTS=<dir> PLAYWRIGHT=<path to playwright> node bench_prove_browser.mjs [runs]

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { syntheticInput } from './aa_input.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = process.env.AA_ARTIFACTS;
if (!dir) throw new Error('Set AA_ARTIFACTS to the directory holding the Anon Aadhaar v2.0.0 artifacts.');
const { chromium } = await import(process.env.PLAYWRIGHT || 'playwright');
const runs = Number(process.argv[2] ?? 3);

const FILES = {
  '/snarkjs.min.js': [path.join(here, 'node_modules/snarkjs/build/snarkjs.min.js'), 'text/javascript'],
  '/circuit.wasm': [path.join(dir, 'aadhaar-verifier.wasm'), 'application/wasm'],
  '/circuit.zkey': [path.join(dir, 'circuit_final.zkey'), 'application/octet-stream'],
  '/vkey.json': [path.join(dir, 'vkey.json'), 'application/json'],
};
const inputs = [];
const server = http.createServer((req, res) => {
  if (req.url === '/') {
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end('<!doctype html><script src="/snarkjs.min.js"></script>');
  }
  const m = req.url.match(/^\/input-(\d+)\.json$/);
  if (m) {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(inputs[Number(m[1])]));
  }
  const file = FILES[req.url];
  if (!file) return res.writeHead(404).end();
  res.writeHead(200, { 'content-type': file[1], 'content-length': fs.statSync(file[0]).size });
  fs.createReadStream(file[0]).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

// Chromium processes (browser, renderer, GPU, utility) as [pid, rss KB].
const chromiumProcesses = () =>
  execFileSync('ps', ['-eo', 'pid=,rss=,comm='], { encoding: 'utf8' })
    .trim()
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .filter(([, , comm]) => /chrom|headless_shell/i.test(comm))
    .map(([pid, rss]) => [Number(pid), Number(rss)]);

// Resident memory of the Chromium processes this run started, in MB.
const before = new Set(chromiumProcesses().map(([pid]) => pid));
const ownRssMB = () =>
  Math.round(chromiumProcesses().filter(([pid]) => !before.has(pid)).reduce((sum, [, rss]) => sum + rss, 0) / 1024);

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
const page = await browser.newPage();
await page.goto(base);
const version = await browser.version();
const results = [];
for (let i = 0; i < runs; i++) {
  inputs[i] = syntheticInput().input;
  let peak = 0;
  const sampler = setInterval(() => {
    peak = Math.max(peak, ownRssMB());
  }, 200);
  const r = await page.evaluate(async (n) => {
    const input = await (await fetch(`/input-${n}.json`)).json();
    const vkey = await (await fetch('/vkey.json')).json();
    const t0 = performance.now();
    const { proof, publicSignals } = await window.snarkjs.groth16.fullProve(input, '/circuit.wasm', '/circuit.zkey');
    const t1 = performance.now();
    const valid = await window.snarkjs.groth16.verify(vkey, publicSignals, proof);
    return { fullProveMs: Math.round(t1 - t0), valid, jsHeapMB: Math.round((performance.memory?.usedJSHeapSize ?? 0) / 2 ** 20) };
  }, i);
  clearInterval(sampler);
  if (!r.valid) throw new Error('Proof did not verify.');
  results.push({ ...r, peakBrowserRssMB: peak });
  console.log(JSON.stringify(results.at(-1)));
}
await browser.close();
server.close();

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const summary = {
  when: new Date().toISOString(),
  machine: { cpu: os.cpus()[0].model, cores: os.cpus().length, memGB: Math.round(os.totalmem() / 2 ** 30) },
  browser: `Chromium ${version} (headless)`,
  note: 'fullProve = witness + proof, with the 612 MB zkey served from localhost (no network cost).',
  runs: results,
  medianFullProveMs: median(results.map((r) => r.fullProveMs)),
  maxPeakBrowserRssMB: Math.max(...results.map((r) => r.peakBrowserRssMB)),
};
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
fs.writeFileSync(path.join(here, 'results/prove_browser.json'), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify({ medianFullProveMs: summary.medianFullProveMs, maxPeakBrowserRssMB: summary.maxPeakBrowserRssMB }));

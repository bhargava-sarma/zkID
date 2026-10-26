#!/usr/bin/env node
// Runs the phone benchmark page (frontend/public/bench/) in headless Chromium:
// the same code a phone runs, downloading the artifacts from Anon Aadhaar's host
// and proving in a Web Worker. Samples the memory of Chromium's processes.
//
// Usage: node bench/browser.mjs [runs]   (PLAYWRIGHT=<path> if playwright is not resolvable)
// First: node bench/make-phone-bench.mjs, and node ../../frontend/scripts/prepare-bench.mjs

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const site = path.join(here, '..', '..', '..', 'frontend', 'public', 'bench');
const playwright = await import(process.env.PLAYWRIGHT || 'playwright');
const { chromium } = playwright.chromium ? playwright : playwright.default; // ESM or CommonJS entry
const runs = Number(process.argv[2] ?? 1);

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  const file = path.join(site, path.normalize(new URL(req.url, 'http://x').pathname.replace(/^\/+/, '')) || 'index.html');
  if (!file.startsWith(site) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return res.writeHead(404).end();
  res.writeHead(200, { 'content-type': TYPES[path.extname(file)] ?? 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${server.address().port}/index.html`;

// Resident memory of the Chromium processes this script started, in MB.
const chromiumProcesses = () =>
  execFileSync('ps', ['-eo', 'pid=,rss=,comm='], { encoding: 'utf8' })
    .trim()
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .filter(([, , comm]) => /chrom|headless_shell/i.test(comm))
    .map(([pid, rss]) => [Number(pid), Number(rss)]);
const before = new Set(chromiumProcesses().map(([pid]) => pid));
const ownRssMB = () => Math.round(chromiumProcesses().filter(([pid]) => !before.has(pid)).reduce((s, [, rss]) => s + rss, 0) / 1024);

const browser = await chromium.launch();
const results = [];
for (let i = 0; i < runs; i++) {
  const page = await browser.newPage();
  await page.goto(url);
  let peak = 0;
  const sampler = setInterval(() => (peak = Math.max(peak, ownRssMB())), 250);
  await page.click('#run');
  await page.waitForSelector('#result:not([hidden])', { timeout: 20 * 60 * 1000 });
  clearInterval(sampler);
  const result = JSON.parse(await page.textContent('#result'));
  if (result.error || !result.stages?.verify?.valid) throw new Error(`run ${i + 1} failed: ${result.error ?? 'proof did not verify'}`);
  results.push({ ...result, peakChromiumRssMB: peak });
  console.log(JSON.stringify({ totalMs: result.totalMs, stages: result.stages, peakChromiumRssMB: peak }));
  await page.close();
}
const version = browser.version();
await browser.close();
server.close();

const summary = {
  when: new Date().toISOString(),
  machine: { cpu: os.cpus()[0].model, cores: os.cpus().length, memGB: Math.round(os.totalmem() / 2 ** 30) },
  browser: `Chromium ${version} (headless)`,
  note: 'The phone benchmark page: artifacts downloaded from Anon Aadhaar host, proving key from its 10 gzip parts, proving in a Web Worker.',
  runs: results.map(({ device, ...r }) => r),
};
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
fs.writeFileSync(path.join(here, 'results', 'chromium.json'), JSON.stringify(summary, null, 2) + '\n');

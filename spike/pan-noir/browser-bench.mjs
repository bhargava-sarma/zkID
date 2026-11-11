#!/usr/bin/env node
// Runs the browser test page (build/web, from `npm run web`) in headless
// Chromium (apps/demo-rp's Playwright) and samples the browser's memory.
// Barretenberg's setup points are served from Node's cache (~/.bb-crs, filled
// by any Node proof), since this sandbox's Chromium cannot reach Aztec's CDN.
// Usage: node browser-bench.mjs [--single]   (--single: no cross-origin
// isolation, so one thread only)

import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { BUILD, HERE } from './circuit.mjs';

const single = process.argv.includes('--single');
const root = path.join(BUILD, 'web');
const crs = path.join(os.homedir(), '.bb-crs');
const playwright = await import(process.env.PLAYWRIGHT || path.join(HERE, '..', '..', 'apps', 'demo-rp', 'node_modules', 'playwright', 'index.mjs'));

const types = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm' };
const server = http.createServer((req, res) => {
  const file = path.join(root, decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/\/$/, '/index.html'));
  if (!file.startsWith(root) || !fs.existsSync(file)) return res.writeHead(404).end();
  const headers = { 'content-type': types[path.extname(file)] || 'application/octet-stream' };
  if (!single) Object.assign(headers, { 'cross-origin-opener-policy': 'same-origin', 'cross-origin-embedder-policy': 'require-corp' });
  res.writeHead(200, headers);
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(4403, r));

// The browser's processes' anonymous memory, summed.
const anonMB = () => {
  let kb = 0;
  for (const pid of fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d))) {
    try {
      const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
      if (/^Name:\s*(headless_shell|chrome)/m.test(status)) kb += Number((status.match(/^RssAnon:\s*(\d+)/m) || [])[1] || 0);
    } catch {}
  }
  return Math.round(kb / 1024);
};
let peak = 0;
const sampler = setInterval(() => (peak = Math.max(peak, anonMB())), 250);

const CRS_FILES = { 'g1_compressed.dat': 'bn254_g1_compressed.dat', 'g2.dat': 'bn254_g2.dat', 'grumpkin_g1_v2.dat': 'grumpkin_g1_v2.flat.dat' };
const browser = await (playwright.chromium ?? playwright.default.chromium).launch();
const context = await browser.newContext({ serviceWorkers: 'block' });
await context.route(/^https:\/\/crs\.aztec-(cdn\.foundation|labs\.com)\//, async (route) => {
  const name = new URL(route.request().url()).pathname.slice(1);
  const file = CRS_FILES[name] && path.join(crs, CRS_FILES[name]);
  if (!file || !fs.existsSync(file)) return route.fulfill({ status: 404 });
  const data = fs.readFileSync(file);
  const range = /bytes=(\d+)-(\d+)/.exec(route.request().headers().range || '');
  const [start, end] = range ? [Number(range[1]), Number(range[2])] : [0, data.length - 1];
  if (end >= data.length) throw new Error(`${name}: asked for bytes up to ${end}, the cache has ${data.length}`);
  await route.fulfill({
    status: range ? 206 : 200,
    headers: { 'access-control-allow-origin': '*', 'cross-origin-resource-policy': 'cross-origin', ...(range ? { 'content-range': `bytes ${start}-${end}/${data.length}` } : {}) },
    body: data.subarray(start, end + 1),
  });
});
const page = await context.newPage();
page.on('pageerror', (e) => console.log('page error:', e.message));
await page.goto(`http://localhost:4403/${single ? '?threads=1' : ''}`);
await page.click('#start');
await page.waitForSelector('#result:not([hidden])', { timeout: 20 * 60 * 1000 });
const text = await page.textContent('#result-text');
clearInterval(sampler);
await browser.close();
server.close();
console.log(`${text}\nBrowser peak anonymous memory: ${(peak / 1024).toFixed(2)} GiB`);

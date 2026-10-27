// End to end against the hosted demo's build (vercel/build.mjs), served as
// Vercel serves it (vercel/serve-output.mjs) from a copy outside the
// repository, so a file the function needs but the build left out fails here
// rather than on Vercel. The holder app's demo build is on one domain (port
// 4100, under /holder/), shops A and B on two others (4101, 4102), state in a
// stand-in for Upstash Redis. The QR is a sample downloaded from shop A.
//
// Run: npm run test:e2e (with flow.test.ts). Needs the frontend's packages
// installed and Chromium (npx playwright install chromium).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROOF_TIMEOUT, holderFlows, qrNeedles, readQr } from './helpers.ts';

const rpDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const HOLDER = 'http://localhost:4100/holder/';
const [A, B] = ['http://localhost:4101', 'http://localhost:4102'];

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'zkid-hosted-'));
const output = path.join(work, 'output');
const sample = path.join(work, 'sample-qr.png');
const minorSample = path.join(work, 'sample-qr-under-19.png');
const servers: ChildProcess[] = [];
let browser: any;
const captured: { url: string; method: string; body: string | null }[] = [];

// The build's output, served as Vercel would, with the stand-in Redis and the
// default holder address whatever this shell has set, and `env` on top.
function serve(ports: number[], env: Record<string, string> = {}) {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(KV_REST_API_|UPSTASH_REDIS_REST_|ZKID_DEMO_HOLDER)/.test(k)));
  const server = spawn(process.execPath, [path.join(rpDir, 'vercel', 'serve-output.mjs'), '--output', output, '--ports', ports.join(',')], {
    stdio: 'inherit',
    env: { ...clean, ...env },
  });
  servers.push(server);
  return server;
}

// The first answer from url, whatever its status, once the server is up.
async function firstAnswer(url: string) {
  for (let i = 0; i < 200; i++) {
    const res = await fetch(url).catch(() => null);
    if (res) return res;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${url} did not start`);
}

async function download(url: string, file: string) {
  const res = await fetch(url);
  assert.equal(res.status, 200, url);
  assert.equal(res.headers.get('content-type'), 'image/png');
  assert.match(res.headers.get('content-disposition') ?? '', /^attachment; filename="zkid-synthetic-test-qr-(adult|under-19)\.png"$/);
  fs.writeFileSync(file, Buffer.from(await res.arrayBuffer()));
}

before(async () => {
  execFileSync(process.execPath, [path.join(rpDir, 'vercel', 'build.mjs')], { stdio: 'inherit' });
  fs.cpSync(path.join(rpDir, '.vercel', 'output'), output, { recursive: true });
  serve([4100, 4101, 4102]);
  assert.equal((await firstAnswer(`${A}/`)).status, 200);
  await download(`${A}/sample-qr.png`, sample);
  await download(`${A}/sample-qr.png?minor`, minorSample);
  const playwright = await import(process.env.PLAYWRIGHT || 'playwright');
  browser = await (playwright.chromium ?? playwright.default.chromium).launch();
});

after(async () => {
  await browser?.close();
  servers.forEach((s) => s.kill());
  fs.rmSync(work, { recursive: true, force: true });
});

let context: any;
async function contextOnce() {
  if (!context) {
    context = await browser.newContext();
    context.on('request', (r: any) => captured.push({ url: r.url(), method: r.method(), body: r.postData() }));
  }
  return context;
}

const { proveAt, proveViaRequestQr } = holderFlows(contextOnce, HOLDER, sample);
let first: any;

test("hosted: the holder's domain sends / to the holder app", async () => {
  const res = await fetch('http://localhost:4100/', { redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/holder/');
});

test("hosted: without the holder's address, every shop says what to set", async () => {
  const server = serve([4110, 4111], { ZKID_DEMO_HOLDER: 'https://holder.example/' }); // not .../holder/
  const res = await firstAnswer('http://localhost:4111/');
  const text = await res.text();
  server.kill();
  assert.equal(res.status, 500);
  assert.match(text, /^The zkID demo is not configured\. Set ZKID_DEMO_HOLDER, as https:\/\/<the holder's domain>\/holder\/\./);
});

test('hosted: shop A accepts a proof from a sample QR, and grants one account', { timeout: PROOF_TIMEOUT }, async () => {
  first = await proveAt(A);
  assert.match(first.answer, /Accepted/);
  assert.equal(first.status.account, 1);
});

test('hosted: shop B, reached through its request QR, sees a different nullifier', { timeout: PROOF_TIMEOUT }, async () => {
  const second = await proveViaRequestQr(B);
  assert.equal(second.status.ok, true);
  assert.notEqual(second.status.nullifier, first.status.nullifier);
});

test('hosted: shop A still shows its account, and refuses a second one (NULLIFIER_SEEN)', { timeout: PROOF_TIMEOUT }, async () => {
  const page = await (await contextOnce()).newPage();
  await page.goto(`${A}/`);
  assert.match(await page.textContent('[data-testid=granted]'), /account here is #1/);
  await page.close();
  await context.clearCookies();
  const again = await proveAt(A);
  assert.equal(again.status.code, 'NULLIFIER_SEEN');
});

test('hosted: a sample QR of someone under 19 is stopped before proving', async () => {
  const page = await (await contextOnce()).newPage();
  await page.goto(`${A}/`);
  await page.click('text=Verify age with zkID');
  await page.waitForSelector('text=asks you to prove');
  await page.setInputFiles('input[type=file]', minorSample);
  assert.match(await page.textContent('[data-testid=error]'), /NOT_19/);
  await page.close();
});

test('hosted: no request the browser made carries any part of the QR', () => {
  assert.ok(captured.some((r) => r.url.includes('circuit_final_0.gz')), 'worker requests are captured');
  const needles = qrNeedles(readQr(fs.readFileSync(sample)));
  for (const r of captured) {
    for (const needle of needles) {
      assert.ok(!r.url.includes(needle) && !(r.body ?? '').includes(needle), `${r.method} ${r.url} carries part of the QR`);
    }
  }
});

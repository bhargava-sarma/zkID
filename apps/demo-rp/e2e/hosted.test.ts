// End to end against the hosted demo's build (vercel/build.mjs), served as
// Vercel serves it (vercel/serve-output.mjs) from a copy outside the
// repository, so a file the function needs but the build left out fails here
// rather than on Vercel. The holder app's demo build is on one domain (port
// 4100, under /holder/), shops A and B on two others (4101, 4102), state in a
// stand-in for Upstash Redis. The QRs are test QRs made by shop A. The last
// tests set a visitor's rules on gender, PIN code and state (T6.1, T6.4).
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
const sample = path.join(work, 'sample-qr.png'); // a man in Bengaluru, 560034, Karnataka (the default)
const minorSample = path.join(work, 'sample-qr-under-19.png');
const herSample = path.join(work, 'sample-qr-her.png'); // a woman in Bengaluru
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
  assert.match(res.headers.get('content-disposition') ?? '', /^attachment; filename="zkid-synthetic-test-qr-(adult|under-19)-[MFT]-[0-9]{6}\.png"$/);
  fs.writeFileSync(file, Buffer.from(await res.arrayBuffer()));
}

before(async () => {
  execFileSync(process.execPath, [path.join(rpDir, 'vercel', 'build.mjs')], { stdio: 'inherit' });
  fs.cpSync(path.join(rpDir, '.vercel', 'output'), output, { recursive: true });
  serve([4100, 4101, 4102]);
  assert.equal((await firstAnswer(`${A}/`)).status, 200);
  await download(`${A}/sample-qr.png`, sample);
  await download(`${A}/sample-qr.png?minor`, minorSample);
  await download(`${A}/sample-qr.png?age=adult&gender=F&pin=560034&state=Karnataka`, herSample);
  assert.equal((await fetch(`${A}/sample-qr.png?gender=X`)).status, 400);
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
  assert.match(await page.textContent('[data-testid=granted]'), /account here is #001/);
  await page.close();
  await context.clearCookies();
  const again = await proveAt(A);
  assert.equal(again.status.code, 'NULLIFIER_SEEN');
});

test('hosted: a sample QR of someone under 19 is stopped before proving', async () => {
  const page = await (await contextOnce()).newPage();
  await page.goto(`${A}/`);
  await page.click('[data-testid=verify]');
  await page.waitForSelector('text=asks you to prove');
  await page.setInputFiles('input[type=file]', minorSample);
  assert.match(await page.textContent('[data-testid=error]'), /NOT_19/);
  await page.close();
});

// Sets shop A's rules through its form, as a visitor does, whatever they were.
async function setRulesAtA({ age19, genders = [], pin = '', states = [] }: { age19: boolean; genders?: string[]; pin?: string; states?: string[] }) {
  const page = await (await contextOnce()).newPage();
  await page.goto(`${A}/`);
  const set = async (input: string, on: boolean) => {
    if ((await page.locator(input).isChecked()) !== on) await page.click(`label:has(${input})`);
  };
  await set('input[name=age19]', age19);
  for (const g of ['M', 'F', 'T']) await set(`input[name=gender][value=${g}]`, genders.includes(g));
  await page.fill('#pin', pin);
  if (!(await page.locator('[data-testid=rules-form] details').evaluate((d: any) => d.open))) await page.click('[data-testid=rules-form] summary');
  for (const st of await page.locator('input[name=state]').evaluateAll((inputs: any[]) => inputs.map((i) => i.value))) {
    await set(`input[name=state][value="${st}"]`, states.includes(st));
  }
  await page.click('[data-testid=save-rules]');
  await page.waitForURL(`${A}/`);
  const chips = await page.textContent('[data-testid=rules]');
  await page.close();
  return chips;
}

test("hosted: rules a visitor gets wrong are not saved, and the page says why", async () => {
  const res = await fetch(`${A}/rules`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'age19=on&pin=0123' });
  assert.equal(res.status, 400);
  assert.match(await res.text(), /data-testid="rules-error"[^>]*>Those rules were not saved: rules\.pinCode has an invalid value: &#34;0123&#34;/);
});

test('T6.4 (hosted): a QR that breaks the rules is stopped before proving, and nothing is sent', async () => {
  const chips = await setRulesAtA({ age19: true, genders: ['F'] });
  assert.match(chips, /19 or older/i);
  assert.match(chips, /Gender: Female/i);
  const proofsPosted = () => captured.filter((r) => r.method === 'POST' && r.url.includes('/zkid/response/')).length;
  const before = proofsPosted();
  const page = await (await contextOnce()).newPage();
  await page.goto(`${A}/`);
  await page.click('[data-testid=verify]');
  await page.waitForSelector('text=asks you to prove');
  await page.setInputFiles('input[type=file]', sample); // a man
  assert.match(await page.textContent('[data-testid=error]'), /accepts only these genders: Female\. Your QR shows Male.*GENDER_NOT_ACCEPTED/);
  await page.close();
  assert.equal(proofsPosted(), before, 'no proof was posted');
});

let ruled: any;
test("hosted: a QR that meets a visitor's rules on gender, PIN code and state is accepted, and the shop shows what it learned", { timeout: PROOF_TIMEOUT }, async () => {
  const chips = await setRulesAtA({ age19: true, genders: ['F', 'T'], pin: '5600xx, 110001', states: ['Karnataka', 'Kerala'] });
  assert.match(chips, /PIN: 5600xx \/ 110001/i);
  assert.match(chips, /State: Karnataka \/ Kerala/i);
  const holder = await (await contextOnce()).newPage();
  await holder.goto(`${A}/`);
  await holder.click('[data-testid=verify]');
  await holder.waitForSelector('text=asks you to prove');
  await holder.setInputFiles('input[type=file]', herSample);
  const shown = await holder.textContent('[data-testid=disclosure]');
  for (const value of ['19 or older', 'Female', '560034', 'Karnataka']) assert.ok(shown.includes(value), `${value} is shown before proving: ${shown}`);
  await holder.close();
  ruled = await proveAt(A, herSample);
  assert.match(ruled.answer, /Accepted/);
  assert.deepEqual(ruled.status.disclosed, { gender: 'F', pinCode: '560034', state: 'Karnataka' });
  const page = await (await contextOnce()).newPage();
  await page.goto(`${A}/`);
  const learned = await page.textContent('[data-testid=learned]');
  await page.close();
  for (const value of ['Female', '560034', 'Karnataka']) assert.ok(learned.includes(value), learned);
});

test('T6.1 (hosted, rules): every proof posted reveals the fields its rules name, and no other', () => {
  const posts = captured.filter((r) => r.method === 'POST' && /\/zkid\/response\//.test(r.url)).map((r) => JSON.parse(r.body ?? '').publicSignals);
  assert.ok(posts.length >= 2, `${posts.length} proofs posted`);
  const packed = (text: string) => [...Buffer.from(text, 'latin1')].reduceRight((v, b) => (v << 8n) | BigInt(b), 0n).toString();
  const last = posts.at(-1);
  assert.deepEqual(last.slice(3, 7), ['1', String('F'.charCodeAt(0)), '560034', packed('Karnataka')]);
  for (const signals of posts.slice(0, -1)) assert.deepEqual(signals.slice(3, 7), ['1', '0', '0', '0'], 'the age-only proofs reveal nothing else');
});

test('T6.3 (hosted): no request the browser made carries any part of either QR it proved with', () => {
  assert.ok(captured.some((r) => r.url.includes('circuit_final_0.gz')), 'worker requests are captured');
  const needles = [sample, herSample].flatMap((file) => qrNeedles(readQr(fs.readFileSync(file))));
  for (const r of captured) {
    for (const needle of needles) {
      assert.ok(!r.url.includes(needle) && !(r.body ?? '').includes(needle), `${r.method} ${r.url} carries part of the QR`);
    }
  }
});

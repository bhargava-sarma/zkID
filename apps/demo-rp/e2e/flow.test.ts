// End to end in headless Chromium, Phase 5 acceptance. Two demo verifiers
// (ports 4101 and 4102) send the browser to the holder app (a demo build on
// 4100), which reads a SYNTHETIC QR image, proves on the page, and posts back
// only the proof. Verifier B is reached through its request QR, as from a
// phone. Checks:
//   - THREAT_MODEL T6.3: no request the browser makes carries any part of the QR;
//   - T6.1: the proof reveals only the age bit (gender, PIN code, state are 0);
//   - the same person gets different nullifiers at the two verifiers, and a
//     second account at the same verifier is refused (NULLIFIER_SEEN).
//
// Run: npm run test:e2e (builds the holder app in demo mode first; downloads
// the circuit artifacts from Anon Aadhaar's host once). Needs Chromium:
// npx playwright install chromium. PLAYWRIGHT=<path> uses another Playwright.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import jsqr from 'jsqr';
// @ts-expect-error pngjs ships no types
import { PNG } from 'pngjs';
import { decodeSecureQr } from '../../../packages/secure-qr/secure-qr.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const rpDir = path.join(here, '..');
const frontend = path.join(rpDir, '..', '..', 'frontend');
const HOLDER = 'http://localhost:4100';
const [A, B] = ['http://localhost:4101', 'http://localhost:4102'];
const PROOF_TIMEOUT = 15 * 60 * 1000;

const children: ChildProcess[] = [];
let staticServer: http.Server;
let browser: any;
const captured: { url: string; method: string; body: string | null }[] = [];

function serveDist() {
  const dist = path.join(frontend, 'dist');
  const types: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' };
  return http.createServer((req, res) => {
    const pathname = new URL(req.url ?? '/', HOLDER).pathname;
    let file = path.join(dist, path.normalize(pathname));
    if (!file.startsWith(dist) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(dist, 'index.html');
    res.writeHead(200, { 'content-type': types[path.extname(file)] ?? 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
}

async function waitFor(url: string) {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${url} did not start`);
}

before(async () => {
  execFileSync(process.execPath, [path.join(rpDir, 'setup-demo.mjs')], { stdio: 'inherit' });
  execFileSync('npm', ['run', 'build:demo'], { cwd: frontend, stdio: 'inherit' });
  staticServer = serveDist();
  await new Promise<void>((r) => staticServer.listen(4100, r));
  for (const port of [4101, 4102]) {
    const child = spawn(process.execPath, [path.join(rpDir, 'server.ts'), '--port', String(port), '--demo', '--holder', HOLDER], { stdio: 'inherit' });
    children.push(child);
    await waitFor(`http://localhost:${port}/`);
  }
  const playwright = await import(process.env.PLAYWRIGHT || 'playwright');
  browser = await (playwright.chromium ?? playwright.default.chromium).launch();
});

after(async () => {
  await browser?.close();
  children.forEach((c) => c.kill());
  staticServer?.close();
});

// One browser context throughout: the holder app caches the circuit after the
// first download. Every request any page or worker makes is recorded.
let context: any;
async function contextOnce() {
  if (!context) {
    context = await browser.newContext();
    context.on('request', (r: any) => captured.push({ url: r.url(), method: r.method(), body: r.postData() }));
  }
  return context;
}

// jsqr is CommonJS; its typed default export is the module's `default`.
const readQr = (png: Buffer) => {
  const image = PNG.sync.read(png);
  const found = jsqr.default(new Uint8ClampedArray(image.data), image.width, image.height);
  assert.ok(found, 'no QR in the image');
  return found.data;
};

// In the holder app, from the request to the verifier's answer.
async function proveOnHolder(page: any) {
  await page.waitForSelector('text=asks you to prove');
  await page.setInputFiles('input[type=file]', path.join(rpDir, '.demo', 'synthetic-qr.png'));
  await page.waitForSelector('[data-testid=qr-ok]');
  await page.click('button:has-text("Prove and send")');
  await page.waitForSelector('[data-testid=answer]', { timeout: PROOF_TIMEOUT });
  return page.textContent('[data-testid=answer]');
}

const statusOf = (page: any) => page.evaluate(async () => (await fetch('/zkid/status')).json());

// The whole flow at one verifier, on one device; returns the verifier's view of the result.
async function proveAt(verifier: string) {
  const page = await (await contextOnce()).newPage();
  await page.goto(`${verifier}/`);
  await page.click('text=Verify age with zkID');
  await page.waitForURL(`${HOLDER}/**`);
  const answer = await proveOnHolder(page);
  await page.click('[data-testid=answer] a');
  await page.waitForURL(`${verifier}/`);
  const status = await statusOf(page);
  await page.close();
  return { answer, status };
}

// The verifier's page shows the request as a QR; a second page (the phone)
// opens what the QR says and proves; the first page picks up the result.
async function proveViaRequestQr(verifier: string) {
  const ctx = await contextOnce();
  const desktop = await ctx.newPage();
  await desktop.goto(`${verifier}/`);
  await desktop.click('text=Verify on my phone');
  const target = readQr(await (await desktop.waitForSelector('[data-testid=request-qr]')).screenshot());
  assert.ok(target.startsWith(`${HOLDER}/?request=`), target);
  const phone = await ctx.newPage();
  await phone.goto(target);
  const answer = await proveOnHolder(phone);
  await desktop.waitForSelector('[data-testid=granted], [data-testid=refused]', { timeout: 30_000 });
  const status = await statusOf(desktop);
  await Promise.all([phone.close(), desktop.close()]);
  return { answer, status };
}

let first: any;

test('a verifier accepts a proof made from a synthetic QR, and grants one account', { timeout: PROOF_TIMEOUT }, async () => {
  first = await proveAt(A);
  assert.match(first.answer, /Accepted/);
  assert.equal(first.status.ok, true);
  assert.equal(first.status.account, 1);
});

test('another verifier, reached through its request QR, sees a different nullifier for the same person', { timeout: PROOF_TIMEOUT }, async () => {
  const second = await proveViaRequestQr(B);
  assert.match(second.answer, /Accepted/);
  assert.equal(second.status.ok, true);
  assert.notEqual(second.status.nullifier, first.status.nullifier);
});

test('a second account at the same verifier is refused: NULLIFIER_SEEN', { timeout: PROOF_TIMEOUT }, async () => {
  await context.clearCookies(); // a new session at A, as if from another browser
  const again = await proveAt(A);
  assert.match(again.answer, /Refused/);
  assert.equal(again.status.code, 'NULLIFIER_SEEN');
});

test('T6.1: what reached the verifiers is a proof and nine signals; gender, PIN code and state are 0', () => {
  const posts = captured.filter((r) => r.method === 'POST' && /\/zkid\/response\//.test(r.url));
  assert.equal(posts.length, 3);
  for (const post of posts) {
    const body = JSON.parse(post.body ?? '');
    assert.deepEqual(Object.keys(body).sort(), ['proof', 'publicSignals']);
    assert.equal(body.publicSignals.length, 9);
    assert.deepEqual(body.publicSignals.slice(4, 7), ['0', '0', '0']);
  }
});

test('T6.3: no request carries any part of the QR', async () => {
  // The circuit artifacts (worker requests) and the proofs were captured, so the
  // capture covers the worker as well as the page.
  assert.ok(captured.some((r) => r.url.includes('circuit_final_0.gz')), 'worker requests are captured');

  const digits = readQr(fs.readFileSync(path.join(rpDir, '.demo', 'synthetic-qr.png')));
  const qr = decodeSecureQr(digits) as unknown as { signedData: Buffer; photo: { offset: number; length: number }; fields: Record<string, Buffer> };
  const signedHex = Buffer.from(qr.signedData).toString('hex');
  const photo = Buffer.from(qr.signedData.subarray(qr.photo.offset, qr.photo.offset + qr.photo.length));
  const needles = [
    ...[0, 1000, digits.length - 40].map((i) => digits.slice(i, i + 40)),
    ...[0, 400, 1200, signedHex.length - 64].map((i) => signedHex.slice(i, i + 64)),
    photo.subarray(100, 140).toString('base64'),
    photo.subarray(100, 132).toString('hex'),
    ...['name', 'careOf', 'district', 'house', 'street', 'vtc', 'dob'].map((f) => Buffer.from(qr.fields[f]).toString('utf8')),
  ];
  assert.ok(needles.every((n) => n.length >= 8));
  for (const r of captured) {
    for (const needle of needles) {
      assert.ok(!r.url.includes(needle) && !(r.body ?? '').includes(needle), `${r.method} ${r.url} carries part of the QR`);
    }
  }
});

// Shared by the end-to-end tests: reading QR images, driving the holder app in
// a browser, and the parts of a QR that no request may carry.
import assert from 'node:assert/strict';
import jsqr from 'jsqr';
// @ts-expect-error pngjs ships no types
import { PNG } from 'pngjs';
import { decodeSecureQr } from '../../../packages/secure-qr/secure-qr.mjs';

export const PROOF_TIMEOUT = 15 * 60 * 1000;

// The text of the QR in a PNG. jsqr is CommonJS; its typed default export is the module's `default`.
export const readQr = (png: Buffer) => {
  const image = PNG.sync.read(png);
  const found = jsqr.default(new Uint8ClampedArray(image.data), image.width, image.height);
  assert.ok(found, 'no QR in the image');
  return found.data;
};

// Stretches of a QR that must never appear in a request: its digits, its signed
// bytes, its photo, and the text of its fields.
export function qrNeedles(digits: string) {
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
  return needles;
}

// The flows through a holder app whose pages start with `holderPrefix`, proving with the QR image `qrFile`.
export function holderFlows(context: () => Promise<any>, holderPrefix: string, qrFile: string) {
  // In the holder app, from the request to the verifier's answer.
  async function proveOnHolder(page: any) {
    await page.waitForSelector('text=asks you to prove');
    await page.setInputFiles('input[type=file]', qrFile);
    await page.waitForSelector('[data-testid=qr-ok]');
    await page.click('button:has-text("Prove and send")');
    await page.waitForSelector('[data-testid=answer]', { timeout: PROOF_TIMEOUT });
    return page.textContent('[data-testid=answer]');
  }

  const statusOf = (page: any) => page.evaluate(async () => (await fetch('/zkid/status')).json());

  // The whole flow at one verifier, on one device; returns the verifier's view of the result.
  async function proveAt(verifier: string) {
    const page = await (await context()).newPage();
    await page.goto(`${verifier}/`);
    await page.click('text=Verify age with zkID');
    await page.waitForURL(`${holderPrefix}**`);
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
    const ctx = await context();
    const desktop = await ctx.newPage();
    await desktop.goto(`${verifier}/`);
    await desktop.click('text=Verify on my phone');
    const target = readQr(await (await desktop.waitForSelector('[data-testid=request-qr]')).screenshot());
    assert.ok(target.startsWith(`${holderPrefix}?request=`), target);
    const phone = await ctx.newPage();
    await phone.goto(target);
    const answer = await proveOnHolder(phone);
    await desktop.waitForSelector('[data-testid=granted], [data-testid=refused]', { timeout: 30_000 });
    const status = await statusOf(desktop);
    await Promise.all([phone.close(), desktop.close()]);
    return { answer, status };
  }

  return { proveOnHolder, statusOf, proveAt, proveViaRequestQr };
}

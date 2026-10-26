// The image reader must return exactly the QR's digits, from PNG and JPEG.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import jpeg from 'jpeg-js';
import { PNG } from 'pngjs';
import QRCode from 'qrcode';
import { readQrImage } from '../read-qr-image.mjs';
import { decodeSecureQr, verifySignature } from '../secure-qr.mjs';
import { makeSyntheticSecureQr } from '../synthetic.mjs';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qr-image-'));
const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const { text } = makeSyntheticSecureQr(keys.privateKey);
const png = path.join(dir, 'qr.png');
fs.writeFileSync(png, await QRCode.toBuffer(text, { type: 'png', errorCorrectionLevel: 'M', margin: 4, scale: 4 }));

test('a synthetic Secure QR survives image -> text -> verify (PNG)', () => {
  const read = readQrImage(png);
  assert.equal(read, text);
  const qr = decodeSecureQr(read);
  assert.equal(verifySignature(qr.signedData, qr.signature, keys.publicKey), true);
});

test('the same from a JPEG photo of the screen', () => {
  const { width, height, data } = PNG.sync.read(fs.readFileSync(png));
  const jpg = path.join(dir, 'qr.jpg');
  fs.writeFileSync(jpg, jpeg.encode({ width, height, data }, 90).data);
  assert.equal(readQrImage(jpg), text);
});

test('negative controls: no QR, a non-Aadhaar QR, or a non-image file fail clearly', async () => {
  const blank = new PNG({ width: 200, height: 200 });
  blank.data.fill(255);
  const blankFile = path.join(dir, 'blank.png');
  fs.writeFileSync(blankFile, PNG.sync.write(blank));
  assert.throws(() => readQrImage(blankFile), /No QR code found/);

  const url = path.join(dir, 'url.png');
  fs.writeFileSync(url, await QRCode.toBuffer('https://example.com', { type: 'png' }));
  assert.throws(() => readQrImage(url), /not an Aadhaar Secure QR/);

  const notImage = path.join(dir, 'a.txt');
  fs.writeFileSync(notImage, '12345');
  assert.throws(() => readQrImage(notImage), /Not a PNG or JPEG/);
});

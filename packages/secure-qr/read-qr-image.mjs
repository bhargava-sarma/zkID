#!/usr/bin/env node
// Reads the Secure QR from a screenshot or photo (PNG or JPEG) and saves its
// decimal text for verify-qr.mjs and compare-downloads.mjs. Runs locally:
// nothing is uploaded, and the QR's contents are never printed.
//
// Usage: node read-qr-image.mjs local/qr-a.png local/a.txt

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import jpeg from 'jpeg-js';
import jsQR from 'jsqr';
import { PNG } from 'pngjs';

export function readQrImage(file) {
  const bytes = fs.readFileSync(file);
  let image;
  if (bytes[0] === 0x89 && bytes.subarray(1, 4).toString() === 'PNG') image = PNG.sync.read(bytes);
  else if (bytes[0] === 0xff && bytes[1] === 0xd8) image = jpeg.decode(bytes, { useTArray: true, maxMemoryUsageInMB: 1024 });
  else throw new Error('Not a PNG or JPEG image.');

  const found = jsQR(new Uint8ClampedArray(image.data.buffer, image.data.byteOffset, image.data.length), image.width, image.height);
  if (!found) throw new Error('No QR code found. Zoom in so the QR fills most of the image, keep a white border, and retake.');
  const text = found.data.trim();
  if (!/^[0-9]+$/.test(text)) throw new Error('That QR code is not an Aadhaar Secure QR (its text is not a decimal number).');
  return text;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [input, output] = process.argv.slice(2);
  if (!input || !output) {
    console.error('Usage: node read-qr-image.mjs <image.png|jpg> <output.txt>');
    process.exit(2);
  }
  try {
    const text = readQrImage(input);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, `${text}\n`);
    console.log(`wrote ${output} (${text.length} digits). Next: node verify-qr.mjs ${output}`);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

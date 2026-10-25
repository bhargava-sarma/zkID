#!/usr/bin/env node
// Phase 1.3: which signed fields stay the same across two downloads of the
// same person's Secure QR? Prints equal/different and byte lengths only, never
// values, so its output can be shared.
//
// Usage: node compare-downloads.mjs <qrA.txt> <qrB.txt> [--cert <file>...]
// Keep the inputs in spike/secure-qr/local/ (gitignored).

import crypto from 'node:crypto';
import fs from 'node:fs';
import { decodeSecureQr, findSigner, parseReferenceId } from './secure-qr.mjs';
import { loadUidaiCerts } from './certs.mjs';

const args = process.argv.slice(2);
const [fileA, fileB] = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--cert');
if (!fileA || !fileB) {
  console.error('Usage: node compare-downloads.mjs <qrA.txt> <qrB.txt> [--cert <file>...]');
  process.exit(2);
}
const extra = args
  .flatMap((a, i) => (a === '--cert' ? [args[i + 1]] : []))
  .map((p) => ({ label: p, cert: new crypto.X509Certificate(fs.readFileSync(p)) }));

const certs = [...loadUidaiCerts(), ...extra];
const [a, b] = [fileA, fileB].map((f) => decodeSecureQr(fs.readFileSync(f, 'utf8')));
const signerOf = (qr) => findSigner(qr, certs)?.label ?? 'none of the known UIDAI certificates';
const row = (name, x, y) =>
  console.log(`${name.padEnd(22)} ${x.equals(y) ? 'same     ' : 'DIFFERENT'}  ${x.length} / ${y.length} bytes`);

console.log(`format                 ${a.version}/${a.compression} vs ${b.version}/${b.compression}`);
console.log(`signed by              A: ${signerOf(a)}; B: ${signerOf(b)}`);
console.log('');
for (const name of Object.keys(a.fields)) {
  if (name === 'referenceId') continue;
  if (b.fields[name]) row(name, a.fields[name], b.fields[name]);
}

// The reference ID is two things: the last 4 Aadhaar digits and a timestamp.
const [ra, rb] = [a, b].map((qr) => parseReferenceId(qr.fields.referenceId));
console.log(`${'referenceId.last4'.padEnd(22)} ${ra.aadhaarLast4 === rb.aadhaarLast4 ? 'same' : 'DIFFERENT'}`);
const hours = Math.abs(ra.generatedAt - rb.generatedAt) / 3.6e6;
console.log(`${'referenceId.time'.padEnd(22)} ${hours === 0 ? 'same' : `DIFFERENT (${hours.toFixed(1)} h apart)`}`);

const photo = (qr) => qr.signedData.subarray(qr.photo.offset, qr.photo.offset + qr.photo.length);
row('photo (JPEG 2000)', photo(a), photo(b));
const trailing = (qr) => qr.signedData.subarray(qr.photo.offset + qr.photo.length);
row('bytes after photo', trailing(a), trailing(b));
row('signature', a.signature, b.signature);

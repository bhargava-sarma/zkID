#!/usr/bin/env node
// Verifies a Secure QR's UIDAI signature and prints its structure. Prints no
// personal values: no name, DOB, address, ID digits or photo bytes.
//
// Usage: node verify-qr.mjs <file with the QR's decimal text | -> [--cert <pem>...]
// Keep real QR files in spike/secure-qr/local/ (gitignored). Exit 0 only if a
// certificate verifies and both negative controls are rejected.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { decodeSecureQr, findSigner, parseReferenceId, verifySignature } from './secure-qr.mjs';
import { loadUidaiCerts } from './certs.mjs';

const args = process.argv.slice(2);
const file = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--cert');
if (!file) {
  console.error('Usage: node verify-qr.mjs <qr-text-file | -> [--cert <pem>...]');
  process.exit(2);
}
const extra = args
  .flatMap((a, i) => (a === '--cert' ? [args[i + 1]] : []))
  .map((p) => ({ label: p, cert: new crypto.X509Certificate(fs.readFileSync(p)) }));

const text = fs.readFileSync(file === '-' ? 0 : file, 'utf8');
const qr = decodeSecureQr(text);
const certs = [...loadUidaiCerts(), ...extra];

console.log(`format        ${qr.version}, ${qr.compression}, ${qr.compressedLength} compressed bytes`);
console.log(`signed data   ${qr.signedData.length} bytes (+ ${qr.signature.length}-byte signature)`);
console.log(`text fields   ${Object.keys(qr.fields).length}; lengths ${Object.values(qr.fields).map((f) => f.length).join(',')}`);
console.log(`photo         JPEG 2000, ${qr.photo.length} bytes at offset ${qr.photo.offset}`);
console.log(`after photo   ${qr.trailingBytes} bytes`);
try {
  console.log(`generated     ${parseReferenceId(qr.fields.referenceId).generatedAt.toISOString().slice(0, 10)} (date only)`);
} catch (err) {
  console.log(`generated     unreadable (${err.code})`);
}

const signer = findSigner(qr, certs);
if (!signer) {
  console.log(`signature     NOT verified by any of ${certs.length} certificates`);
  process.exit(1);
}
const { cert } = signer;
console.log(`signature     VALID under ${signer.label} (${cert.validFrom} to ${cert.validTo})`);

// Negative controls: the same check must reject one changed byte.
const tamperedData = Buffer.from(qr.signedData);
tamperedData[Math.floor(tamperedData.length / 2)] ^= 0x01;
const tamperedSig = Buffer.from(qr.signature);
tamperedSig[tamperedSig.length - 1] ^= 0x01;
const controls = [
  ['one flipped bit in the signed data', verifySignature(tamperedData, qr.signature, cert)],
  ['one flipped bit in the signature', verifySignature(qr.signedData, tamperedSig, cert)],
];
for (const [label, accepted] of controls) console.log(`control       ${label}: ${accepted ? 'ACCEPTED (FAIL)' : 'rejected'}`);
process.exit(controls.some(([, accepted]) => accepted) ? 1 : 0);

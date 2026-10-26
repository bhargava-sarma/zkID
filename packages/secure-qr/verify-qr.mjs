#!/usr/bin/env node
// Verifies a Secure QR's UIDAI signature and prints its structure. Prints no
// personal values: no name, DOB, address, ID digits or photo bytes.
//
// Usage: node verify-qr.mjs <file with the QR's decimal text | -> [--cert <pem>...]
// Keep real QR files in packages/secure-qr/local/ (gitignored). Exit 0 only if a
// certificate verifies, both negative controls are rejected and the layout is known.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { SecureQrError, decodeEnvelope, findSigner, parseReferenceId, parseSignedData, verifySignature } from './secure-qr.mjs';
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

// Printed so the owner can compare a downloaded certificate with UIDAI's listing.
for (const { label, cert } of extra) {
  const cn = cert.subject.split('\n').find((l) => l.startsWith('CN='))?.slice(3);
  console.log(`--cert        ${label}: "${cn}", valid ${cert.validFrom} to ${cert.validTo}`);
  console.log(`              sha256 fingerprint ${cert.fingerprint256}`);
}

const text = fs.readFileSync(file === '-' ? 0 : file, 'utf8');
const envelope = decodeEnvelope(text);
const certs = [...loadUidaiCerts(), ...extra];
console.log(`envelope      ${envelope.compression}, ${envelope.compressedLength} compressed bytes`);
console.log(`signed data   ${envelope.signedData.length} bytes (+ ${envelope.signature.length}-byte signature)`);

// The signature does not depend on the field layout, so it is checked first.
const signer = findSigner(envelope, certs);
if (!signer) {
  console.log(`signature     NOT verified by any of ${certs.length} certificates`);
  process.exit(1);
}
const { cert } = signer;
console.log(`signature     VALID under ${signer.label} (${cert.validFrom} to ${cert.validTo})`);

// Negative controls: the same check must reject one changed byte.
const tamperedData = Buffer.from(envelope.signedData);
tamperedData[Math.floor(tamperedData.length / 2)] ^= 0x01;
const tamperedSig = Buffer.from(envelope.signature);
tamperedSig[tamperedSig.length - 1] ^= 0x01;
const controls = [
  ['one flipped bit in the signed data', verifySignature(tamperedData, envelope.signature, cert)],
  ['one flipped bit in the signature', verifySignature(envelope.signedData, tamperedSig, cert)],
];
for (const [label, accepted] of controls) console.log(`control       ${label}: ${accepted ? 'ACCEPTED (FAIL)' : 'rejected'}`);
if (controls.some(([, accepted]) => accepted)) process.exit(1);

let qr;
try {
  qr = parseSignedData(envelope.signedData);
} catch (err) {
  if (!(err instanceof SecureQrError)) throw err;
  console.log(`layout        ${err.message}`);
  console.log(`              To describe it without printing values: node inspect-qr.mjs ${args.join(' ')}`);
  process.exit(1);
}
console.log(`format        ${qr.version}`);
console.log(`text fields   ${Object.keys(qr.fields).length}; lengths ${Object.values(qr.fields).map((f) => f.length).join(',')}`);
console.log(`photo         JPEG 2000, ${qr.photo.length} bytes at offset ${qr.photo.offset}`);
console.log(`after photo   ${qr.trailingBytes} bytes`);
try {
  console.log(`generated     ${parseReferenceId(qr.fields.referenceId).generatedAt.toISOString().slice(0, 10)} (date only)`);
} catch (err) {
  console.log(`generated     unreadable (${err.code})`);
}

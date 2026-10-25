// Run: npm test (in spike/secure-qr). Every acceptance is paired with rejections.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';
import {
  SecureQrError,
  bytesToQrText,
  decodeSecureQr,
  findSigner,
  parseReferenceId,
  verifySignature,
} from '../secure-qr.mjs';
import { buildSignedData, makeSyntheticSecureQr, signAndEncode, syntheticFields, syntheticPhoto, unknownTrailer } from '../synthetic.mjs';
import { loadUidaiCerts } from '../certs.mjs';

const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const UIDAI = loadUidaiCerts();
const SAMPLE = fileURLToPath(new URL('../local/uidai-official-sample-v1.txt', import.meta.url));

const rejectsWith = (code, fn) => assert.throws(fn, (err) => err instanceof SecureQrError && err.code === code);
const encodeRaw = (data) => bytesToQrText(zlib.gzipSync(data));

test('a synthetic V2 QR parses into the fields it was built from', () => {
  const generatedAt = new Date('2026-10-20T06:30:00.000Z');
  const fields = syntheticFields({ generatedAt, dob: '15-08-2001' });
  const qr = decodeSecureQr(makeSyntheticSecureQr(keys.privateKey, { fields }).text);
  assert.equal(qr.version, 'V2');
  assert.equal(qr.compression, 'gzip');
  assert.equal(Object.keys(qr.fields).length, 17);
  for (const name of Object.keys(qr.fields)) assert.equal(qr.fields[name].toString('utf8'), fields[name], name);
  assert.equal(qr.photo.length, 888);
  assert.equal(qr.trailingBytes, 0);
  assert.deepEqual(parseReferenceId(qr.fields.referenceId), { aadhaarLast4: '0000', generatedAt });
  assert.equal(verifySignature(qr.signedData, qr.signature, keys.publicKey), true);
});

test('a synthetic V5 code with the measured shape parses: 17 fields, photo, 27 bytes after', () => {
  const photo = syntheticPhoto(900);
  const qr = decodeSecureQr(makeSyntheticSecureQr(keys.privateKey, { version: 'V5', photo, trailing: unknownTrailer() }).text);
  assert.equal(qr.version, 'V5');
  assert.equal(qr.fields.mobile.toString(), 'xxxxxx0000');
  assert.equal(qr.fields.mobileLast4, undefined);
  assert.deepEqual([qr.photo.length, qr.trailingBytes], [900, 27]);
  assert.equal(verifySignature(qr.signedData, qr.signature, keys.publicKey), true);
});

test('synthetic samples are labelled as such', () => {
  const qr = decodeSecureQr(makeSyntheticSecureQr(keys.privateKey).text);
  assert.match(qr.fields.name.toString(), /SYNTHETIC/);
  assert.match(qr.fields.careOf.toString(), /NOT A REAL AADHAAR/);
});

test('negative control: one changed byte anywhere in the signed data is rejected', () => {
  const qr = decodeSecureQr(makeSyntheticSecureQr(keys.privateKey).text);
  const dob = qr.delimiterIndices[3] + 1; // first DOB digit
  const positions = [0, qr.delimiterIndices[5], dob, qr.photo.offset + 100, qr.signedData.length - 1];
  for (const i of positions) {
    const tampered = Buffer.from(qr.signedData);
    tampered[i] ^= 0x01;
    assert.equal(verifySignature(tampered, qr.signature, keys.publicKey), false, `byte ${i}`);
  }
});

test('negative control: a changed signature, or the wrong key, is rejected', () => {
  const qr = decodeSecureQr(makeSyntheticSecureQr(keys.privateKey).text);
  const sig = Buffer.from(qr.signature);
  sig[0] ^= 0x80;
  assert.equal(verifySignature(qr.signedData, sig, keys.publicKey), false);
  assert.equal(verifySignature(qr.signedData, qr.signature, otherKeys.publicKey), false);
});

test('negative control: a synthetic QR never verifies against a UIDAI certificate', () => {
  const qr = decodeSecureQr(makeSyntheticSecureQr(keys.privateKey).text);
  assert.equal(UIDAI.length, 4);
  assert.equal(findSigner(qr, UIDAI), null);
});

test('zlib-compressed QR data decodes too, and says so', () => {
  const qr = decodeSecureQr(makeSyntheticSecureQr(keys.privateKey, { compression: 'zlib' }).text);
  assert.equal(qr.compression, 'zlib');
  assert.equal(verifySignature(qr.signedData, qr.signature, keys.publicKey), true);
});

test('0xFF bytes inside the photo do not shift the text fields', () => {
  const photo = syntheticPhoto(888);
  photo.fill(0xff, 10, 60);
  const qr = decodeSecureQr(makeSyntheticSecureQr(keys.privateKey, { photo }).text);
  assert.equal(qr.fields.mobileLast4.toString(), '0000');
  assert.equal(qr.photo.length, 888);
});

test('malformed inputs fail with explicit codes', () => {
  rejectsWith('NOT_DECIMAL', () => decodeSecureQr('12ab34'));
  rejectsWith('UNSUPPORTED_COMPRESSION', () => decodeSecureQr(bytesToQrText(crypto.randomBytes(300).fill(0x11, 0, 2))));
  rejectsWith('CORRUPT_COMPRESSION', () => decodeSecureQr(bytesToQrText(Buffer.concat([Buffer.from([0x1f, 0x8b]), crypto.randomBytes(100)]))));
  rejectsWith('TOO_SHORT', () => decodeSecureQr(encodeRaw(crypto.randomBytes(256))));
  rejectsWith('UNSUPPORTED_VERSION', () => decodeSecureQr(makeSyntheticSecureQr(keys.privateKey, { version: 'V9' }).text));
  rejectsWith('MALFORMED', () => decodeSecureQr(encodeRaw(Buffer.alloc(600, 0x41))));
  const noPhoto = buildSignedData({ photo: Buffer.from('not a photo at all') });
  rejectsWith('PHOTO_NOT_JPEG2000', () => decodeSecureQr(signAndEncode(noPhoto, keys.privateKey).text));
  rejectsWith('MALFORMED_REFERENCE_ID', () => parseReferenceId('1234'));
  rejectsWith('MALFORMED_REFERENCE_ID', () => parseReferenceId('000020261399120000000'));
});

test('certs/registry.json matches the certificate files', () => {
  for (const { cert, meta } of UIDAI) {
    assert.equal(cert.publicKey.asymmetricKeyDetails.modulusLength, 2048, meta.file);
    assert.equal(cert.publicKey.asymmetricKeyDetails.publicExponent, 65537n, meta.file);
    assert.equal(new Date(cert.validTo).toISOString(), meta.not_after, meta.file);
  }
});

test('UIDAI official sample (V1) verifies under the 2017-2020 UIDAI key', { skip: fs.existsSync(SAMPLE) ? false : 'run npm run fetch-uidai-sample first' }, () => {
  const qr = decodeSecureQr(fs.readFileSync(SAMPLE, 'utf8'));
  assert.equal(qr.version, 'V1');
  assert.equal(qr.compression, 'gzip');
  assert.equal(qr.signedData.length, 1129);
  assert.equal(qr.photo.length, 888);
  assert.equal(qr.trailingBytes, 64); // mobile and email hashes, indicator 3
  const signer = findSigner(qr, UIDAI);
  assert.equal(signer?.label, 'uidai-ds-4_2017-2020.crt');
  for (const { label, cert } of UIDAI.filter((c) => c !== signer)) {
    assert.equal(verifySignature(qr.signedData, qr.signature, cert), false, label);
  }

  // Generated inside that certificate's validity window.
  const { generatedAt } = parseReferenceId(qr.fields.referenceId);
  assert.ok(generatedAt >= new Date(signer.cert.validFrom) && generatedAt <= new Date(signer.cert.validTo));

  const tampered = Buffer.from(qr.signedData);
  tampered[qr.delimiterIndices[2] + 1] ^= 0x01; // a DOB byte
  assert.equal(verifySignature(tampered, qr.signature, signer.cert), false);
});

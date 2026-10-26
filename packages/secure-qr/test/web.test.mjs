// web.mjs, the holder app's decoder (DecompressionStream, WebCrypto), against
// the Node decoder. THREAT_MODEL tests T7.3 and T7.5.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import * as node from '../secure-qr.mjs';
import * as web from '../web.mjs';
import { buildSignedData, makeSyntheticSecureQr, signAndEncode, syntheticPhoto, unknownTrailer } from '../synthetic.mjs';
import { loadUidaiCerts } from '../certs.mjs';

const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const modulusHex = (publicKey) => Buffer.from(publicKey.export({ format: 'jwk' }).n, 'base64url').toString('hex');
const SAMPLE = fileURLToPath(new URL('../local/uidai-official-sample-v1.txt', import.meta.url));
const v5 = () => makeSyntheticSecureQr(keys.privateKey, { version: 'V5', photo: syntheticPhoto(900), trailing: unknownTrailer(27) }).text;

test('web and Node decoders agree on V5 (gzip) and V2 (zlib) codes', async () => {
  for (const text of [v5(), makeSyntheticSecureQr(keys.privateKey, { compression: 'zlib' }).text]) {
    const [a, b] = [node.decodeSecureQr(text), await web.decodeSecureQr(text)];
    assert.deepEqual(
      [b.version, b.compression, b.photo, b.trailingBytes, b.delimiterIndices],
      [a.version, a.compression, a.photo, a.trailingBytes, a.delimiterIndices],
    );
    assert.deepEqual(Buffer.from(b.signedData), Buffer.from(a.signedData));
    for (const name of Object.keys(a.fields)) assert.deepEqual(Buffer.from(b.fields[name]), Buffer.from(a.fields[name]), name);
  }
});

test('the signature verifies under the signing key only', async () => {
  const qr = await web.decodeSecureQr(v5());
  const [own, other] = await Promise.all([keys, otherKeys].map((k) => web.importRsaKey(modulusHex(k.publicKey))));
  assert.equal(await web.verifySignature(qr.signedData, qr.signature, own), true);
  assert.equal(await web.verifySignature(qr.signedData, qr.signature, other), false);
  assert.equal((await web.findSigner(qr, [{ id: 'other', cryptoKey: other }, { id: 'own', cryptoKey: own }]))?.id, 'own');
  assert.equal(await web.findSigner(qr, [{ id: 'other', cryptoKey: other }]), null);
});

test('T7.3: every signed byte, flipped one at a time, fails the signature check', async () => {
  const qr = await web.decodeSecureQr(v5());
  const key = await web.importRsaKey(modulusHex(keys.publicKey));
  const tampered = new Uint8Array(qr.signedData);
  for (let i = 0; i < tampered.length; i++) {
    tampered[i] ^= 0x01;
    assert.equal(await web.verifySignature(tampered, qr.signature, key), false, `byte ${i}`);
    tampered[i] ^= 0x01;
  }
  assert.equal(await web.verifySignature(tampered, qr.signature, key), true, 'restored');
  assert.ok(tampered.length > 1000, 'the whole signed data of a V5-sized code was covered');
});

test('T7.5: malformed QR text fails with the same typed codes as in Node', async () => {
  const encodeRaw = (data) => node.bytesToQrText(zlib.gzipSync(data));
  const cases = [
    ['NOT_DECIMAL', '12ab34'],
    ['UNSUPPORTED_COMPRESSION', node.bytesToQrText(crypto.randomBytes(300).fill(0x11, 0, 2))],
    ['CORRUPT_COMPRESSION', node.bytesToQrText(Buffer.concat([Buffer.from([0x1f, 0x8b]), crypto.randomBytes(100)]))],
    ['TOO_SHORT', encodeRaw(crypto.randomBytes(256))],
    ['UNSUPPORTED_VERSION', makeSyntheticSecureQr(keys.privateKey, { version: 'V9' }).text],
    ['MALFORMED', encodeRaw(Buffer.alloc(600, 0x41))],
    ['PHOTO_NOT_JPEG2000', signAndEncode(buildSignedData({ photo: Buffer.from('not a photo at all') }), keys.privateKey).text],
  ];
  for (const [code, text] of cases) {
    await assert.rejects(web.decodeSecureQr(text), (err) => err instanceof web.SecureQrError && err.code === code, code);
    assert.throws(() => node.decodeSecureQr(text), (err) => err.code === code, `node: ${code}`);
  }
});

test("UIDAI's official sample verifies under the 2017-2020 key with WebCrypto", { skip: fs.existsSync(SAMPLE) ? false : 'run npm run fetch-uidai-sample first' }, async () => {
  const qr = await web.decodeSecureQr(fs.readFileSync(SAMPLE, 'utf8'));
  const certs = await Promise.all(
    loadUidaiCerts().map(async ({ label, cert }) => ({ id: label, cryptoKey: await web.importRsaKey(modulusHex(cert.publicKey)) })),
  );
  assert.equal((await web.findSigner(qr, certs))?.id, 'uidai-ds-4_2017-2020.crt');
});

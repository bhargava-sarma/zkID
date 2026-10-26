// Holder app logic, in Node (no browser): request checks (THREAT_MODEL T5.4,
// T6.2), QR checks, and what the circuit input reveals (T6.1). Run: npm test.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { acceptServedRequest, publicInputsFor } from './request.js';
import { checkQr, inputFor } from './qr.js';
import { HolderError } from './errors.js';
import { importRsaKey } from '../../../packages/secure-qr/web.mjs';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../../../packages/secure-qr/synthetic.mjs';
import { nullifierSeedFor, signalHashFor } from '../../../packages/verifier-sdk/src/request.ts';

const A = 'https://shop.example';
const NOW = Date.parse('2026-10-26T06:00:00Z') / 1000;
const request = { version: 1, verifierId: A, challenge: 'ab'.repeat(32), maxAgeSeconds: 7 * 86400, expiresAt: NOW + 300 };
const served = (overrides = {}, requestOverrides = {}) => ({
  request: { ...request, ...requestOverrides },
  responseUrl: `${A}/zkid/response/x`,
  returnUrl: `${A}/`,
  ...overrides,
});
const rejectsWith = (fn, code) => assert.throws(fn, (e) => e instanceof HolderError && e.code === code, code);

test('a well-formed request from the verifier origin is accepted', () => {
  const accepted = acceptServedRequest(`${A}/zkid/request/x`, served(), NOW);
  assert.deepEqual(accepted, { request, responseUrl: `${A}/zkid/response/x`, returnUrl: `${A}/` });
});

test('T5.4: a request is refused unless it, and the addresses it names, are on the verifier origin', () => {
  rejectsWith(() => acceptServedRequest('https://evil.example/zkid/request/x', served(), NOW), 'WRONG_ORIGIN');
  rejectsWith(() => acceptServedRequest(`${A}/r`, served({ responseUrl: 'https://evil.example/collect' }), NOW), 'WRONG_ORIGIN');
  rejectsWith(() => acceptServedRequest(`${A}/r`, served({ returnUrl: 'https://evil.example/' }), NOW), 'WRONG_ORIGIN');
});

test('T6.2: a request asking for anything more than "19 or older" is refused', () => {
  rejectsWith(() => acceptServedRequest(`${A}/r`, served({}, { reveal: ['gender'] }), NOW), 'UNSUPPORTED_REQUEST');
  rejectsWith(() => acceptServedRequest(`${A}/r`, served({ attributes: ['state', 'pinCode'] }), NOW), 'UNSUPPORTED_REQUEST');
});

test('expired and malformed requests are refused', () => {
  rejectsWith(() => acceptServedRequest(`${A}/r`, served(), request.expiresAt + 1), 'REQUEST_EXPIRED');
  rejectsWith(() => acceptServedRequest(`${A}/r`, served({}, { challenge: 'not hex' }), NOW), 'BAD_REQUEST');
  rejectsWith(() => acceptServedRequest(`${A}/r`, 'a string', NOW), 'BAD_REQUEST');
  rejectsWith(() => acceptServedRequest('not a url', served(), NOW), 'BAD_REQUEST');
});

test("the proof's public inputs are the verifier SDK's seed and signal hash", async () => {
  assert.deepEqual(await publicInputsFor(request), { nullifierSeed: await nullifierSeedFor(A), signalHash: await signalHashFor(request) });
});

// ---- The QR -------------------------------------------------------------------------

const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const strangers = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const modulusHex = (k) => Buffer.from(k.publicKey.export({ format: 'jwk' }).n, 'base64url').toString('hex');
const trusted = async (k, window = { notBefore: 0, notAfter: 2 ** 32 }) => [
  { id: 'test-key', label: 'TEST KEY', modulus: modulusHex(k), cryptoKey: await importRsaKey(modulusHex(k)), ...window },
];
const GENERATED = Date.parse('2026-10-25T06:30:00Z') / 1000; // 12:00 IST
const qr = (fields = {}, photo = syntheticPhoto(900)) =>
  makeSyntheticSecureQr(keys.privateKey, { version: 'V5', photo, trailing: unknownTrailer(27), fields: syntheticFields({ generatedAt: new Date(GENERATED * 1000), ...fields }) }).text;
const checkRejects = (promise, code) => assert.rejects(promise, (e) => e.code === code, code);

test('a QR signed by a trusted key, fresh, of someone 19 or older, passes', async () => {
  const checked = await checkQr(qr(), await trusted(keys), request, NOW);
  assert.equal(checked.signer.id, 'test-key');
  assert.equal(checked.generatedAt.getTime() / 1000, GENERATED);
});

test('a QR that would be refused is caught before proving', async () => {
  await checkRejects(checkQr(qr(), await trusted(strangers), request, NOW), 'UNTRUSTED_QR');
  await checkRejects(checkQr(qr(), await trusted(keys, { notBefore: GENERATED + 3600, notAfter: 2 ** 32 }), request, NOW), 'KEY_NOT_VALID');
  await checkRejects(checkQr(qr(), await trusted(keys), { ...request, maxAgeSeconds: 3600 }, NOW), 'QR_TOO_OLD');
  await checkRejects(checkQr(qr({ dob: '1990' }), await trusted(keys), request, NOW), 'UNSUPPORTED_DOB');
  await checkRejects(checkQr('12ab', await trusted(keys), request, NOW), 'NOT_DECIMAL');
});

test("the age pre-check matches the circuit's boundaries (packages/circuit test T1.10)", async () => {
  // QR generated on 25-10-2026; the circuit gives 1 only from the 19th birthday.
  const expected = { '26-10-2008': false, '25-10-2008': false, '24-10-2008': false, '26-10-2007': false, '25-10-2007': true, '24-10-2007': true };
  for (const [dob, passes] of Object.entries(expected)) {
    const result = checkQr(qr({ dob }), await trusted(keys), request, NOW);
    if (passes) await assert.doesNotReject(result, dob);
    else await checkRejects(result, 'NOT_19');
  }
});

test('T6.1: the circuit input reveals only the age bit, and a photo too large for the circuit is refused', async () => {
  const checked = await checkQr(qr(), await trusted(keys), request, NOW);
  const input = inputFor(checked, await publicInputsFor(request));
  assert.deepEqual([input.revealAgeAbove18, input.revealGender, input.revealPinCode, input.revealState], ['1', '0', '0', '0']);
  const big = await checkQr(qr({}, syntheticPhoto(990)), await trusted(keys), request, NOW);
  assert.throws(() => inputFor(big, { nullifierSeed: 1n, signalHash: 1n }), (e) => e.code === 'PHOTO_TOO_LARGE');
});

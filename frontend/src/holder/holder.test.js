// Holder app logic, in Node (no browser): request checks (THREAT_MODEL T5.4,
// T6.2), QR checks against the request's rules (T6.4), and what the circuit
// input reveals (T6.1). Run: npm test.
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
const request = { version: 2, verifierId: A, challenge: 'ab'.repeat(32), maxAgeSeconds: 7 * 86400, expiresAt: NOW + 300, rules: { age19: true } };
const withRules = (rules) => ({ ...request, rules });
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

test('T6.2: a request with anything beyond the request format, or with malformed rules, is refused', () => {
  rejectsWith(() => acceptServedRequest(`${A}/r`, served({}, { reveal: ['gender'] }), NOW), 'UNSUPPORTED_REQUEST');
  rejectsWith(() => acceptServedRequest(`${A}/r`, served({ attributes: ['state', 'pinCode'] }), NOW), 'UNSUPPORTED_REQUEST');
  for (const rules of [undefined, { age19: true, name: ['X'] }, { age19: true, gender: ['M', 'F', 'T', 'M'] }, { age19: true, pinCode: ['0'] }, { gender: ['M'] }]) {
    rejectsWith(() => acceptServedRequest(`${A}/r`, served({}, { rules }), NOW), 'BAD_REQUEST');
  }
  const rules = { age19: false, gender: ['F'], pinCode: ['5600'], state: ['Karnataka'] };
  assert.deepEqual(acceptServedRequest(`${A}/r`, served({}, { rules }), NOW).request.rules, rules);
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

test('T6.1: the circuit input reveals only what the rules name, and a photo too large for the circuit is refused', async () => {
  const flags = async (rules) => {
    const r = withRules(rules);
    const input = inputFor(await checkQr(qr(BENGALURU), await trusted(keys), r, NOW), await publicInputsFor(r), rules);
    return [input.revealAgeAbove18, input.revealGender, input.revealPinCode, input.revealState];
  };
  assert.deepEqual(await flags({ age19: true }), ['1', '0', '0', '0']);
  assert.deepEqual(await flags({ age19: false, pinCode: ['5600'] }), ['0', '0', '1', '0']);
  assert.deepEqual(await flags({ age19: true, gender: ['F'], state: ['karnataka'] }), ['1', '1', '0', '1']);
  const big = await checkQr(qr({}, syntheticPhoto(990)), await trusted(keys), request, NOW);
  assert.throws(() => inputFor(big, { nullifierSeed: 1n, signalHash: 1n }, request.rules), (e) => e.code === 'PHOTO_TOO_LARGE');
});

const BENGALURU = { gender: 'F', pincode: '560034', state: 'Karnataka' };

test('T6.4: a QR that breaks the rules is refused before proving; one that meets them shows exactly what will be revealed', async () => {
  const keyList = await trusted(keys);
  const check = (rules, fields = BENGALURU) => checkQr(qr(fields), keyList, withRules(rules), NOW);
  await checkRejects(check({ age19: true, gender: ['M', 'T'] }), 'GENDER_NOT_ACCEPTED');
  await checkRejects(check({ age19: true, pinCode: ['110', '5601'] }), 'PIN_CODE_NOT_ACCEPTED');
  await checkRejects(check({ age19: true, state: ['Kerala'] }), 'STATE_NOT_ACCEPTED');
  await checkRejects(check({ age19: true, gender: ['F'] }, { ...BENGALURU, dob: '26-10-2010' }), 'NOT_19');
  // Under 19 is fine when the rules do not ask for age.
  assert.deepEqual((await check({ age19: false, gender: ['F'] }, { ...BENGALURU, dob: '26-10-2010' })).disclosed, { gender: 'F' });
  assert.deepEqual((await check({ age19: true })).disclosed, {});
  assert.deepEqual((await check({ age19: true, gender: ['F'], pinCode: ['5600'], state: ['KARNATAKA'] })).disclosed, { gender: 'F', pinCode: '560034', state: 'Karnataka' });
  const refused = await check({ age19: true, pinCode: ['110'] }).catch((e) => e);
  assert.match(refused.message, /accepts only these PIN codes: 110xxx\. Your QR shows 560034/);
});

test('a QR the circuit cannot read is refused before the download, whatever the rules', async () => {
  const keyList = await trusted(keys);
  await checkRejects(checkQr(qr({ state: 'Dadra and Nagar Haveli and Daman and Diu' }), keyList, request, NOW), 'UNSUPPORTED_STATE');
  await checkRejects(checkQr(qr({ pincode: '56003' }), keyList, request, NOW), 'UNSUPPORTED_PIN_CODE');
  await checkRejects(checkQr(qr({ pincode: '5600AB' }), keyList, withRules({ age19: true, pinCode: ['5600'] }), NOW), 'UNSUPPORTED_PIN_CODE');
  await checkRejects(checkQr(qr({ gender: 'MF' }), keyList, request, NOW), 'UNSUPPORTED_GENDER');
});

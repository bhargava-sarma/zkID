// Run with `npm test`. Proof checks need the verification key: run
// `npm run fetch-circuit` in backend/ first.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { codeFromText, decodeProofCode, encodeProofCode, verifierLink } from './proofCode.js';
import { checkProofCode } from './checkProofCode.js';
import { TRUSTED_ISSUERS } from './trustedIssuers.js';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const { proof, publicSignals } = JSON.parse(fs.readFileSync(here('./fixtures/signed-proof.json'), 'utf8'));
const VKEY = here('../../../backend/circuits/credential-age-proof/verification_key.json');
const vkey = fs.existsSync(VKEY) ? JSON.parse(fs.readFileSync(VKEY, 'utf8')) : null;
const needsVkey = vkey ? false : 'run npm run fetch-circuit in backend/ first';

// The fixture was proved with cutoff 20080928: 18 years before this day.
const PROVED_ON = new Date('2026-09-28T12:00:00Z');
const code = await encodeProofCode(proof, publicSignals);

// snarkjs keeps worker threads for the curve alive between calls.
after(() => globalThis.curve_bn128?.terminate());

test('the trusted issuer is the mock issuer key', () => {
  const pem = fs.readFileSync(here('../../../mock-issuer/mock_issuer_public.pem'), 'utf8');
  const modulus = Buffer.from(crypto.createPublicKey(pem).export({ format: 'jwk' }).n, 'base64url');
  assert.equal(TRUSTED_ISSUERS[0].modulusHex, modulus.toString('hex'));
});

test('a code round-trips and is found in a verifier link', () => {
  assert.equal(code.length, 360);
  const decoded = decodeProofCode(code);
  assert.deepEqual(
    [decoded.proof.pi_a, decoded.proof.pi_b, decoded.proof.pi_c],
    [proof.pi_a, proof.pi_b, proof.pi_c]
  );
  assert.equal(decoded.thresholdDate, 20080928);
  assert.equal(codeFromText(verifierLink(code, 'https://zk-id-lime.vercel.app')), code);
  assert.equal(codeFromText(` ${code}\n`), code);
  assert.equal(codeFromText('https://example.com/?p=abc'), null);
});

test('malformed codes are unreadable, not errors', async () => {
  const wrongVersion = Buffer.from(code, 'base64url');
  wrongVersion[0] = 2;
  for (const text of ['not-a-code', code.slice(0, 200), wrongVersion.toString('base64url')]) {
    const result = await checkProofCode(text, { now: PROVED_ON, vkey });
    assert.equal(result.accepted, false);
    assert.ok(result.unreadable);
  }
});

test('accepted: trusted issuer, valid proof, 18+ today', { skip: needsVkey }, async () => {
  const result = await checkProofCode(code, { now: PROVED_ON, vkey });
  assert.equal(result.accepted, true);
  assert.equal(result.issuer, 'zkID demo issuer');
  assert.equal(result.proofValid, true);
  assert.equal(result.bornOnOrBefore, '2008-09-28');
});

test('still accepted later: age only increases', { skip: needsVkey }, async () => {
  assert.equal((await checkProofCode(code, { now: new Date('2031-01-01T00:00:00Z'), vkey })).accepted, true);
});

test('policy: a valid proof with a too-lax cutoff is rejected', { skip: needsVkey }, async () => {
  // Checked the day before: the proof's cutoff is one day later than 18 years
  // ago, so it would admit someone who is still 17.
  const result = await checkProofCode(code, { now: new Date('2026-09-27T12:00:00Z'), vkey });
  assert.equal(result.proofValid, true);
  assert.equal(result.ageOk, false);
  assert.equal(result.accepted, false);
});

test('policy: a valid proof from a non-allowlisted issuer is rejected', { skip: needsVkey }, async () => {
  const result = await checkProofCode(code, { now: PROVED_ON, vkey, issuers: [] });
  assert.equal(result.issuer, null);
  assert.equal(result.proofValid, null);
  assert.equal(result.accepted, false);
});

test('a corrupted code is rejected', { skip: needsVkey }, async () => {
  const bytes = Buffer.from(code, 'base64url');
  bytes[bytes.length - 1] ^= 1;
  const result = await checkProofCode(bytes.toString('base64url'), { now: PROVED_ON, vkey });
  assert.equal(result.proofValid, false);
  assert.equal(result.accepted, false);
});

// The trusted-issuer list must never contain a key whose private half is public.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TRUSTED_ISSUERS } from './trustedIssuers.js';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const { keys: COMPROMISED } = JSON.parse(fs.readFileSync(here('../../../security/compromised-keys.json'), 'utf8'));
const TEST_FIXTURE = JSON.parse(fs.readFileSync(here('./fixtures/test-signed-proof.json'), 'utf8'));

const normalize = (hex) => hex.toLowerCase().replace(/^0+/, '');
const isCompromised = (issuer) => COMPROMISED.some((k) => normalize(k.modulus_hex) === normalize(issuer.modulusHex));

test('no trusted issuer is a known-compromised key', () => {
  assert.deepEqual(TRUSTED_ISSUERS.filter(isCompromised), []);
});

test('the test fixture key is not trusted', () => {
  assert.equal(TRUSTED_ISSUERS.some((i) => normalize(i.modulusHex) === normalize(TEST_FIXTURE.issuer_modulus_hex)), false);
});

test('negative control: the check flags the v1 demo key, however it is written', () => {
  const v1 = COMPROMISED[0].modulus_hex;
  assert.equal(isCompromised({ modulusHex: v1 }), true);
  assert.equal(isCompromised({ modulusHex: `00${v1.toUpperCase()}` }), true);
  assert.equal(isCompromised({ modulusHex: TEST_FIXTURE.issuer_modulus_hex }), false);
});

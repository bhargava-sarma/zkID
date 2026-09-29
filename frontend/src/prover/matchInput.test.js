// The browser's match input must be exactly what the backend builds and the
// circuit accepted (see backend/hardhat-deploy/test/fixtures).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { buildMatchInput, nameHash, signedFields } from './matchInput.js';

const require = createRequire(import.meta.url);
const backend = require('../../../backend/circuits/credential-match-proof/gen_input.js');
const credential = require('../../../mock-issuer/circuit_inputs.json');
const nameFixture = require('../../../backend/hardhat-deploy/test/fixtures/match-name.json');

test('name hash matches the backend and the proved fixture', () => {
  for (const name of ['Test User One', '  test   USER one ', 'A', 'Venkata Satya Narayana Murthy Chowdary Kondapalli']) {
    assert.equal(nameHash(name), backend.nameHash(name), name);
  }
  assert.equal(nameHash('Test User One'), nameFixture.publicSignals[17]);
});

test('match input matches the backend builder', () => {
  const issued = { msg: credential.message_bytes, signature: credential.signature_limbs, modulus: credential.modulus_limbs };
  for (const claims of [{ name: 'Test User One' }, { gender: 'M' }, { name: 'test user one', gender: 'M' }]) {
    assert.deepEqual(buildMatchInput(issued, claims), backend.buildMatchInput(credential, claims).input);
  }
  assert.deepEqual(signedFields(credential.message_bytes), { name: 'Test User One', gender: 'M' });
});

// A real proof of a SYNTHETIC record: proved with prove.mjs, checked with
// verify.mjs against the pinned verification key, its public inputs in the
// order input.mjs names them; a changed public input or proof fails.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { circuitInput, expectedOutputs, publicValues } from '../input.mjs';
import { prove } from '../prove.mjs';
import { readRecord } from '../record.mjs';
import { makeRecord, testIssuer, testKey } from '../synthetic.mjs';
import { closeVerifier, verifyProof } from '../verify.mjs';

after(closeVerifier);

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const pinned = JSON.parse(fs.readFileSync(new URL('../artifacts/vk.json', import.meta.url), 'utf8'));
const vk = Buffer.from(pinned.vk, 'base64');

test('the pinned verification key belongs to the pinned program', () => {
  assert.equal(sha256(fs.readFileSync(new URL('../artifacts/pan_verifier.json', import.meta.url))), pinned.programSha256);
  assert.equal(sha256(vk), pinned.vkSha256);
});

test('a proof verifies, says what the record holds, and fails if anything in it changes', async () => {
  const issuer = testIssuer();
  const record = await readRecord(await makeRecord(issuer, { dob: '15-06-2000', gender: 'TRANSGENDER' }), [testKey(issuer)]);
  const options = { dobCutoff: 20071027, nullifierSeed: 1111n, signalHash: 2222n, revealGender: true };
  const stages = [];
  const { proof, publicInputs } = await prove(circuitInput(record, options), { threads: 4, onStage: (s) => stages.push(s) });
  assert.deepEqual(stages, ['witness', 'setup', 'prove']);

  assert.equal(await verifyProof({ proof, publicInputs }, vk), true);
  assert.deepEqual(publicValues(publicInputs), { dobCutoff: '20071027', nullifierSeed: '1111', signalHash: '2222', ...expectedOutputs(record, options) });

  for (const i of publicInputs.keys()) {
    const changed = publicInputs.map((x, j) => (j === i ? `0x${(BigInt(x) + 1n).toString(16).padStart(64, '0')}` : x));
    assert.equal(await verifyProof({ proof, publicInputs: changed }, vk), false, `public input ${i}`);
  }
  const mauled = Uint8Array.from(proof);
  mauled[100] ^= 1;
  assert.equal(await verifyProof({ proof: mauled, publicInputs }, vk).catch(() => false), false, 'a changed proof');
});

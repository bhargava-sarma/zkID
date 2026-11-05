// The SHA-1 circuit against node:crypto, through the JS SHA-1 (sha1.mjs).
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import { compress, pad, sha1, stateAfter } from '../sha1.mjs';
import { SPIKE, close, compile, witness } from './helpers.mjs';

after(close);

const bits = (word) => Array.from({ length: 32 }, (_, i) => String((word >>> i) & 1));
const word = (values) => values.reduce((acc, bit, i) => acc + Number(bit) * 2 ** i, 0);

test('the JS SHA-1 matches node:crypto, and its midstates chain', () => {
  for (const length of [0, 1, 55, 56, 63, 64, 119, 563, 2000]) {
    const message = crypto.randomBytes(length);
    assert.deepEqual(sha1(message), crypto.createHash('sha1').update(message).digest(), `length ${length}`);
  }
  const padded = pad(crypto.randomBytes(563));
  assert.deepEqual(compress(stateAfter(padded, 7), padded.subarray(448, 512)), stateAfter(padded, 8));
});

test('two compressions in the circuit match the JS SHA-1 from any state', async () => {
  const wasm = compile(path.join(SPIKE, 'test', 'circuits', 'sha1-two-blocks.circom'));
  for (let round = 0; round < 3; round++) {
    const state = Array.from({ length: 5 }, () => crypto.randomBytes(4).readUInt32BE());
    const blocks = [crypto.randomBytes(64), crypto.randomBytes(64)];
    const w = await witness(wasm, { state: state.map(bits), blocks: blocks.map((b) => [...b].map(String)) });
    const out = Array.from({ length: 5 }, (_, j) => word(w.slice(1 + 32 * j, 33 + 32 * j)));
    assert.deepEqual(out, compress(compress(state, blocks[0]), blocks[1]));
  }
});

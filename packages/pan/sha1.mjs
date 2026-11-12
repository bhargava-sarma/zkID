// SHA-1 in JavaScript, with access to the state between blocks: the circuit
// starts from the state after SignedInfo's constant first blocks. Checked
// against node:crypto in the tests.

const IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
const rotl = (x, s) => ((x << s) | (x >>> (32 - s))) >>> 0;

export function compress(state, block) {
  const w = new Array(80);
  for (let t = 0; t < 16; t++) w[t] = ((block[4 * t] << 24) | (block[4 * t + 1] << 16) | (block[4 * t + 2] << 8) | block[4 * t + 3]) >>> 0;
  for (let t = 16; t < 80; t++) w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
  let [a, b, c, d, e] = state;
  for (let t = 0; t < 80; t++) {
    const [f, k] =
      t < 20 ? [(b & c) | (~b & d), 0x5a827999] : t < 40 ? [b ^ c ^ d, 0x6ed9eba1] : t < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc] : [b ^ c ^ d, 0xca62c1d6];
    const temp = (rotl(a, 5) + (f >>> 0) + e + k + w[t]) >>> 0;
    [e, d, c, b, a] = [d, c, rotl(b, 30), a, temp];
  }
  return [a, b, c, d, e].map((x, i) => (x + state[i]) >>> 0);
}

// Message and SHA-1 padding: 0x80, zeros, the bit length in 64 bits.
export function pad(message) {
  const length = Math.ceil((message.length + 9) / 64) * 64;
  const padded = new Uint8Array(length);
  padded.set(message);
  padded[message.length] = 0x80;
  new DataView(padded.buffer).setBigUint64(length - 8, BigInt(message.length) * 8n);
  return padded;
}

// The state after the first `blocks` blocks of the padded message.
export function stateAfter(padded, blocks) {
  let state = IV;
  for (let i = 0; i < blocks; i++) state = compress(state, padded.subarray(64 * i, 64 * i + 64));
  return state;
}

export const sha1 = (message) => {
  const padded = pad(message);
  const state = stateAfter(padded, padded.length / 64);
  return Buffer.concat(state.map((x) => Buffer.from([x >>> 24, (x >>> 16) & 255, (x >>> 8) & 255, x & 255])));
};

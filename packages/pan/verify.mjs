// Checks a PAN proof against a verification key, for verifiers (Node). It uses
// bb.js's WebAssembly backend, the same everywhere (no native binary), on one
// thread: a check takes milliseconds. One Barretenberg instance per process,
// made on first use.
//
// Checking a proof takes two of Barretenberg's setup points, both fixed: the
// BN254 generator [1]_1, and [x]_2 from Aztec's Ignition ceremony. Both are
// below, so a verifier downloads nothing and keeps nothing on disk. Barretenberg
// also checks [x]_2 against the SHA-256 it pins (01797bfc…) and will not start
// with any other point: that point is what a forged proof would need changed.

import { Barretenberg, BackendType, UltraHonkVerifierBackend } from '@aztec/bb.js';

const G1_GENERATOR = new Uint8Array(64); // (1, 2), each coordinate 32 bytes big-endian
G1_GENERATOR[31] = 1;
G1_GENERATOR[63] = 2;
const G2_X = Uint8Array.from(
  Buffer.from(
    '0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1' +
      '22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e5504fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4',
    'hex',
  ),
);

let instance = null;

async function start() {
  const api = await Barretenberg.new({ threads: 1, backend: BackendType.Wasm, skipSrsInit: true });
  try {
    await api.srsInitSrs({ pointsBuf: G1_GENERATOR, numPoints: 1, g2Point: G2_X });
    return api;
  } catch (err) {
    await api.destroy();
    throw err;
  }
}

// The verifier's Barretenberg instance. Its errors are the verifier's, not the
// proof's: callers let them propagate rather than call the proof bad.
export function ready() {
  instance ??= start().catch((err) => {
    instance = null;
    throw err;
  });
  return instance;
}

// proof: the proof's bytes; publicInputs: 32-byte hex strings; vk: the key's
// bytes. Throws if Barretenberg rejects the proof's encoding.
export async function verifyProof({ proof, publicInputs }, vk) {
  const api = await ready();
  return new UltraHonkVerifierBackend(api).verifyProof({ proof, publicInputs, verificationKey: vk });
}

// Lets the process exit: Barretenberg keeps a worker.
export async function closeVerifier() {
  const api = instance && (await instance.catch(() => null));
  instance = null;
  await api?.destroy();
}

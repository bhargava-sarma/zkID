// Checks a PAN proof against a verification key, for verifiers (Node). It uses
// bb.js's WebAssembly backend, the same everywhere (no native binary), on one
// thread: a check takes milliseconds. One Barretenberg instance per process,
// made on first use, which needs 2^17 of Barretenberg's setup points (about
// 8 MB): read from crsPath if they are there, otherwise downloaded once from
// Aztec's CDN and kept there (default ~/.bb-crs).

import { Barretenberg, BackendType, UltraHonkVerifierBackend } from '@aztec/bb.js';

const SRS_POINTS = 2 ** 17; // the least Barretenberg loads
let instance = null;

// The verifier's Barretenberg instance. Its errors (the setup points cannot be
// read or downloaded, say) are the verifier's, not the proof's: callers let
// them propagate rather than call the proof bad.
export function ready({ crsPath } = {}) {
  instance ??= Barretenberg.new({ threads: 1, backend: BackendType.Wasm, srsSize: SRS_POINTS, ...(crsPath && { crsPath }) }).catch((err) => {
    instance = null;
    throw err;
  });
  return instance;
}

// proof: the proof's bytes; publicInputs: 32-byte hex strings; vk: the key's
// bytes. Throws if Barretenberg rejects the proof's encoding.
export async function verifyProof({ proof, publicInputs }, vk, options) {
  const api = await ready(options);
  return new UltraHonkVerifierBackend(api).verifyProof({ proof, publicInputs, verificationKey: vk });
}

// Lets the process exit: Barretenberg keeps a worker.
export async function closeVerifier() {
  const api = instance && (await instance.catch(() => null));
  instance = null;
  await api?.destroy();
}

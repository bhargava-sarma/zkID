// Proves a record with the pinned circuit: noir_js executes it (the witness),
// and bb.js proves with UltraHonk. The same code runs in browsers and in Node.
// In a browser, initialize noir_js's WebAssembly first (the holder app does),
// and bb.js proves on several threads only when the page is cross-origin
// isolated.

import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import program from './artifacts/pan_verifier.json' with { type: 'json' };

export { program };

// Barretenberg's setup points the circuit needs: its 333,411 gates, rounded up
// to a power of two. The first proof downloads them (16 MB), from Aztec's CDN.
export const SRS_POINTS = 2 ** 19;

// onStage(stage): 'witness', 'setup', then 'prove'. Returns the proof's bytes
// and its public inputs (32-byte hex strings, input.mjs PUBLIC_INPUTS).
export async function prove(input, { threads = 1, onStage } = {}) {
  onStage?.('witness');
  const { witness } = await new Noir(program).execute(input);
  onStage?.('setup');
  const api = await Barretenberg.new({ threads, srsSize: SRS_POINTS });
  try {
    onStage?.('prove');
    const { proof, publicInputs } = await new UltraHonkBackend(program.bytecode, api).generateProof(witness);
    return { proof, publicInputs };
  } finally {
    await api.destroy();
  }
}

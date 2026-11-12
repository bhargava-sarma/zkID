// Proves a checked PAN record on this device with the pinned PAN circuit:
// noir_js executes it and bb.js proves with UltraHonk. App.jsx imports this
// module only when a PAN record is proved, so the Aadhaar flow never loads it
// (about 10 MB). bb.js proves on several threads when the page is
// cross-origin isolated, on one otherwise.
import initACVM from '@noir-lang/acvm_js';
import acvmWasm from '@noir-lang/acvm_js/web/acvm_js_bg.wasm?url';
import initNoirC from '@noir-lang/noirc_abi';
import noircWasm from '@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url';
import { prove } from '../../../packages/pan/prove.mjs';

let ready = null;

// About 1 GB of memory whatever the count (docs/circuit-spec.md, section 7).
export const panThreads = () => (globalThis.crossOriginIsolated ? Math.min(navigator.hardwareConcurrency || 1, 8) : 1);

const toBase64 = (bytes) => btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(''));

// onStage(stage): 'witness', 'setup' (the first proof downloads Barretenberg's
// setup points, about 20 MB), 'prove'. Returns the body the website receives.
export async function provePan(input, { onStage } = {}) {
  ready ??= Promise.all([initACVM(fetch(acvmWasm)), initNoirC(fetch(noircWasm))]);
  await ready;
  const { proof, publicInputs } = await prove(input, { threads: panThreads(), onStage });
  return { document: 'pan', proof: toBase64(proof), publicInputs };
}

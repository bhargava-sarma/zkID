// Runs prove.worker.js, so the page stays responsive while proving.
import manifest from '../../../packages/circuit/artifacts.json' with { type: 'json' };

// VITE_ZKID_ARTIFACTS_URL serves the same files from elsewhere (they are still
// checked against artifacts.json).
const base = import.meta.env.VITE_ZKID_ARTIFACTS_URL || manifest.release;

// Phones crashed proving with several threads (docs/circuit-spec.md, section 5);
// one thread needs about half the memory.
export const lowMemoryDevice = () => (navigator.deviceMemory ?? 8) < 8 || /Android|iPhone|iPad/i.test(navigator.userAgent);

export function prove(input, { singleThread = lowMemoryDevice(), onStage } = {}) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./prove.worker.js', import.meta.url), { type: 'module' });
    const finish = (fn, value) => {
      worker.terminate();
      fn(value);
    };
    worker.onmessage = ({ data }) => {
      if (data.type === 'stage') onStage?.(data);
      else if (data.type === 'done') finish(resolve, { proof: data.proof, publicSignals: data.publicSignals });
      else finish(reject, new Error(data.message));
    };
    worker.onerror = (e) => finish(reject, new Error(e.message || 'The prover could not start.'));
    worker.postMessage({ input, base, manifest, singleThread });
  });
}

// Runs the credential prover in a worker so the UI stays responsive.
// circuit: 'age' (CredentialAgeProof) or 'match' (CredentialMatchProof).
export function proveInBrowser(input, { circuit = 'age', onStage, onProgress } = {}) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./credentialProver.worker.js', import.meta.url), { type: 'module' });
    const finish = (fn, value) => {
      worker.terminate();
      fn(value);
    };
    worker.onmessage = ({ data }) => {
      if (data.type === 'stage') onStage?.(data.stage);
      else if (data.type === 'progress') onProgress?.(data.name, data.pct);
      else if (data.type === 'done') finish(resolve, data);
      else finish(reject, new Error(data.message));
    };
    worker.onerror = (e) => finish(reject, new Error(e.message || 'The prover worker failed to start.'));
    worker.postMessage({ input, circuit });
  });
}

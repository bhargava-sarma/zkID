// Proves the issuer-signed credential in the browser. Artifacts are checked
// against the release SHA-256 and kept in Cache Storage after first use.
import * as snarkjs from 'snarkjs';

const BASE = '/api/circuit';
const CACHE = 'zkid-circuit';

const post = (msg) => self.postMessage(msg);

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function download(entry) {
  const res = await fetch(`${BASE}/${entry.name}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${entry.name}: HTTP ${res.status}`);
  const out = new Uint8Array(entry.bytes);
  const reader = res.body.getReader();
  let offset = 0;
  let lastPct = -1;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (offset + value.length > out.length) throw new Error(`${entry.name}: larger than expected`);
    out.set(value, offset);
    offset += value.length;
    const pct = Math.floor((offset / entry.bytes) * 100);
    if (pct !== lastPct) {
      lastPct = pct;
      post({ type: 'progress', name: entry.name, pct });
    }
  }
  if (offset !== entry.bytes) throw new Error(`${entry.name}: incomplete download`);
  return out;
}

async function loadArtifact(entry) {
  const key = `${BASE}/${entry.name}?sha256=${entry.sha256}`;
  const cache = await caches.open(CACHE);
  const hit = await cache.match(key);
  if (hit) {
    const data = new Uint8Array(await hit.arrayBuffer());
    if ((await sha256Hex(data)) === entry.sha256) return data;
  }
  const data = await download(entry);
  if ((await sha256Hex(data)) !== entry.sha256) throw new Error(`${entry.name}: checksum mismatch`);
  try {
    await cache.put(key, new Response(data));
  } catch {
    // Storage quota: still usable for this proof, just not cached.
  }
  return data;
}

self.onmessage = async ({ data: { input } }) => {
  try {
    const manifest = await (await fetch(`${BASE}/artifacts.json`, { cache: 'no-store' })).json();
    const entry = (name) => manifest.files.find((f) => f.name === name);

    post({ type: 'stage', stage: 'loading' });
    const wasm = await loadArtifact(entry('credential_age_proof.wasm'));
    const zkey = await loadArtifact(entry('cap_final.zkey'));
    const vkey = JSON.parse(new TextDecoder().decode(await loadArtifact(entry('verification_key.json'))));

    post({ type: 'stage', stage: 'proving' });
    const started = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      { type: 'mem', data: wasm },
      { type: 'mem', data: zkey }
    );
    const proofDuration = Math.round(performance.now() - started);

    post({ type: 'stage', stage: 'verifying' });
    const verifyStart = performance.now();
    const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    const verificationDuration = Math.round(performance.now() - verifyStart);

    post({ type: 'done', proof, publicSignals, isValid, proofDuration, verificationDuration });
  } catch (err) {
    post({ type: 'error', message: err?.message || String(err) });
  }
};

// Proves the issuer-signed credential in the browser. Artifacts are static files
// (large ones split into parts), checked against the release SHA-256 and kept in
// Cache Storage after first use.
import * as snarkjs from 'snarkjs';

const BASE = '/circuit';
const CACHE = 'zkid-circuit';

// age: CredentialAgeProof (circuit-v1). match: CredentialMatchProof (name and gender).
const CIRCUITS = {
  age: { wasm: 'credential_age_proof.wasm', zkey: 'cap_final.zkey', vkey: 'verification_key.json' },
  match: { wasm: 'credential_match_proof.wasm', zkey: 'cmp_final.zkey', vkey: 'match_verification_key.json' },
};

const post = (msg) => self.postMessage(msg);

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function download(entry) {
  const out = new Uint8Array(entry.bytes);
  let offset = 0;
  let lastPct = -1;
  for (const part of entry.parts) {
    const res = await fetch(`${BASE}/${part}`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`${part}: HTTP ${res.status}`);
    const reader = res.body.getReader();
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

self.onmessage = async ({ data: { input, circuit = 'age' } }) => {
  try {
    const files = CIRCUITS[circuit];
    if (!files) throw new Error(`Unknown circuit "${circuit}".`);
    const manifest = await (await fetch(`${BASE}/manifest.json`, { cache: 'no-store' })).json();
    const entry = (name) => {
      const found = manifest.files.find((f) => f.name === name);
      if (!found) throw new Error(`${name} is not staged. Run the frontend build again.`);
      return found;
    };

    post({ type: 'stage', stage: 'loading' });
    const wasm = await loadArtifact(entry(files.wasm));
    const zkey = await loadArtifact(entry(files.zkey));
    const vkey = JSON.parse(new TextDecoder().decode(await loadArtifact(entry(files.vkey))));

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

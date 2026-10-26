// Proves in a Web Worker with Anon Aadhaar's circuit. The circuit wasm and the
// proving key (as its 10 gzip parts) come from the artifact host; every file is
// checked against its SHA-256 from packages/circuit/artifacts.json before use,
// and kept in Cache Storage so later proofs skip the 296 MB download.
import * as snarkjs from 'snarkjs';

const CACHE = 'zkid-circuit-v2.0.0';
const post = (message) => self.postMessage(message);

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

// The file's bytes, from the cache or the network, only if its hash matches.
async function checkedFile(url, entry) {
  // No Cache Storage on plain-http pages other than localhost: download every time.
  const cache = typeof caches === 'undefined' ? null : await caches.open(CACHE).catch(() => null);
  let bytes = cache && (await cache.match(url).then((r) => r?.arrayBuffer()));
  if (!bytes || (await sha256Hex(bytes)) !== entry.sha256) {
    const res = await fetch(url, { credentials: 'omit' });
    if (!res.ok) throw new Error(`${entry.name}: HTTP ${res.status}`);
    bytes = await res.arrayBuffer();
    const digest = await sha256Hex(bytes);
    if (digest !== entry.sha256) throw new Error(`${entry.name}: SHA-256 ${digest}, expected ${entry.sha256}`);
    await cache?.put(url, new Response(bytes));
  }
  return bytes;
}

self.onmessage = async ({ data: { input, base, manifest, singleThread } }) => {
  try {
    const wasmEntry = manifest.files.find((f) => f.name === 'aadhaar-verifier.wasm');
    const zkeyEntry = manifest.files.find((f) => f.name === 'circuit_final.zkey');
    post({ type: 'stage', stage: 'download', done: 0, total: manifest.chunkedZkey.files.length + 1 });
    const wasm = new Uint8Array(await checkedFile(`${base}/${wasmEntry.name}`, wasmEntry));

    // Each part is decompressed straight into one buffer of the key's size.
    const zkey = new Uint8Array(zkeyEntry.bytes);
    let offset = 0;
    for (const [i, part] of manifest.chunkedZkey.files.entries()) {
      post({ type: 'stage', stage: 'download', done: i + 1, total: manifest.chunkedZkey.files.length + 1 });
      const gz = await checkedFile(`${base}/${manifest.chunkedZkey.path}/${part.name}`, part);
      const reader = new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
      for (let r = await reader.read(); !r.done; r = await reader.read()) {
        if (offset + r.value.length > zkey.length) throw new Error('The proving key is larger than expected.');
        zkey.set(r.value, offset);
        offset += r.value.length;
      }
    }
    if (offset !== zkey.length) throw new Error(`The proving key is ${offset} bytes, expected ${zkey.length}.`);

    post({ type: 'stage', stage: 'prove' });
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      { type: 'mem', data: wasm },
      { type: 'mem', data: zkey },
      undefined,
      undefined,
      { singleThread },
    );
    post({ type: 'done', proof, publicSignals });
  } catch (err) {
    post({ type: 'error', message: String(err?.message ?? err) });
  }
};

// Proves once with Anon Aadhaar's published circuit on a synthetic input, and
// reports how long each stage took. Runs in a Web Worker.
/* global snarkjs */
importScripts('snarkjs.min.js');

const stage = (name, extra = {}) => postMessage({ type: 'stage', name, ...extra });

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

// Fails unless the bytes match the pinned hash. Without crypto.subtle (a page
// served over plain http from a LAN address) the check cannot run; the result
// says so instead of skipping silently.
async function check(name, buffer, expected, report) {
  if (!self.crypto?.subtle) {
    report.hashesChecked = false;
    return;
  }
  const actual = await sha256Hex(buffer);
  if (actual !== expected) throw new Error(`${name}: SHA-256 ${actual}, expected ${expected}`);
}

async function fetchBytes(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.arrayBuffer();
}

async function run() {
  const bench = await (await fetch('bench-synthetic.json')).json();
  const report = { hashesChecked: true, stages: {} };

  stage('download circuit (wasm)');
  let t = performance.now();
  const wasm = await fetchBytes(`${bench.release}/${bench.wasm.name}`);
  await check(bench.wasm.name, wasm, bench.wasm.sha256, report);
  report.stages.wasm = { ms: Math.round(performance.now() - t), mb: +(wasm.byteLength / 1e6).toFixed(1) };

  // The proving key arrives as 10 gzip parts; each is checked, then
  // decompressed straight into one buffer.
  const zkey = new Uint8Array(bench.zkey.bytes);
  let offset = 0;
  let downloaded = 0;
  t = performance.now();
  for (const [i, part] of bench.zkey.chunks.entries()) {
    stage(`download proving key, part ${i + 1} of ${bench.zkey.chunks.length}`);
    const gz = await fetchBytes(`${bench.release}/${bench.zkey.path}/${part.name}`);
    await check(part.name, gz, part.sha256, report);
    downloaded += gz.byteLength;
    const reader = new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
    for (let r = await reader.read(); !r.done; r = await reader.read()) {
      if (offset + r.value.length > zkey.length) throw new Error('proving key larger than expected');
      zkey.set(r.value, offset);
      offset += r.value.length;
    }
  }
  if (offset !== zkey.length) throw new Error(`proving key is ${offset} bytes, expected ${zkey.length}`);
  report.stages.provingKey = { ms: Math.round(performance.now() - t), downloadedMb: +(downloaded / 1e6).toFixed(1), mb: +(zkey.length / 1e6).toFixed(1) };

  stage('proving (witness + proof)');
  t = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(bench.input, { type: 'mem', data: new Uint8Array(wasm) }, { type: 'mem', data: zkey });
  report.stages.prove = { ms: Math.round(performance.now() - t) };

  stage('verifying');
  t = performance.now();
  const valid = await snarkjs.groth16.verify(bench.vkey, publicSignals, proof);
  report.stages.verify = { ms: Math.round(performance.now() - t), valid };
  return report;
}

run().then(
  (report) => postMessage({ type: 'done', report }),
  (err) => postMessage({ type: 'error', message: String(err?.message ?? err) }),
);

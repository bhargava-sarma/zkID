// The Noir PAN phone test: executes the circuit on a SYNTHETIC record, proves
// it with Barretenberg on one thread and then on all cores (when the page is
// cross-origin isolated), and checks each proof against the verification key.
// It reports times, the device, and where a run stopped if the tab was killed.
// It sends nothing anywhere.

import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend } from '@aztec/bb.js';
import initACVM from '@noir-lang/acvm_js';
import acvmWasm from '@noir-lang/acvm_js/web/acvm_js_bg.wasm?url';
import { Noir } from '@noir-lang/noir_js';
import initNoirC from '@noir-lang/noirc_abi';
import noircWasm from '@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm?url';

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const SRS_POINTS = 2 ** 19; // the circuit's 333,411 gates, rounded up to a power of two
const RUN = 'zkid-pan-noir:run';
const LAST = 'zkid-pan-noir:last';
const store = {
  get: (key) => { try { return JSON.parse(localStorage.getItem(key)); } catch { return null; } },
  set: (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); } catch {} },
  del: (key) => { try { localStorage.removeItem(key); } catch {} },
};
const clock = (s) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(Math.floor(s % 60)).padStart(2, '0')}`;
const secs = (s) => `${s.toFixed(1)} s`;
const since = (t) => (performance.now() - t) / 1000;

// Cross-origin isolation, which threads need. A static host cannot send its
// headers, so a service worker adds them and the page reloads once.
const isolate = async () => {
  if (crossOriginIsolated || params.has('threads') || !('serviceWorker' in navigator)) return;
  if (sessionStorage.getItem('zkid-coi-reloaded')) return; // it did not take: go on without threads
  try {
    await navigator.serviceWorker.register('./coi-sw.js');
    await navigator.serviceWorker.ready;
    sessionStorage.setItem('zkid-coi-reloaded', '1');
    location.reload();
  } catch {}
};
await isolate();
const cores = navigator.hardwareConcurrency || 1;
const modes = params.get('threads') === '1' || !crossOriginIsolated || cores === 1 ? [1] : [1, cores];

let device = `${cores} cores, about ${navigator.deviceMemory || '?'} GB memory reported`;
(async () => {
  try {
    const ua = await navigator.userAgentData.getHighEntropyValues(['model', 'platformVersion', 'fullVersionList']);
    const chrome = (ua.fullVersionList || []).find((b) => /Chrome/.test(b.brand));
    device = `${ua.model || 'unknown model'}, ${ua.platform} ${ua.platformVersion}, ${chrome ? `Chrome ${chrome.version}` : navigator.userAgent}, ${device}`;
  } catch {
    device = `${navigator.userAgent}, ${device}`;
  }
})();

// A run that never reported back means the tab was killed, usually because
// the phone ran out of memory.
const unfinished = store.get(RUN);
const last = store.get(LAST);
if (unfinished) {
  $('crash-text').textContent = [
    'zkID PAN phone test (Noir): the last run did not finish.',
    `It stopped while ${unfinished.stage}, ${clock((unfinished.at - unfinished.startedAt) / 1000)} after it started.`,
    ...(unfinished.done || []),
    'Most likely the phone ran out of memory, unless the page was closed or reloaded.',
    `Device: ${unfinished.device}`,
  ].join('\n');
  $('crash').hidden = false;
  store.del(RUN);
} else if (last) {
  $('result-text').textContent = `Previous result\n\n${last}`;
  $('result').hidden = false;
}

let run = null;
let wakeLock = null;
const keepAwake = async () => {
  try {
    wakeLock = await navigator.wakeLock.request('screen');
  } catch {
    run && run.notes.add('could not keep the screen on automatically');
  }
};
document.addEventListener('visibilitychange', () => {
  if (!run) return;
  if (document.visibilityState === 'hidden') run.notes.add('the tab went to the background during the test, so timings may be off');
  else keepAwake();
});

function stage(text) {
  $('stage').textContent = text;
  Object.assign(run.state, { stage: text.toLowerCase(), at: Date.now() });
  store.set(RUN, run.state);
}
function done(line) {
  run.lines.push(line);
  run.state.done = run.lines;
  store.set(RUN, run.state);
}

async function test() {
  stage('Loading the circuit');
  const fetched = (path) => fetch(path).then((r) => {
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
    return r;
  });
  await Promise.all([initACVM(fetch(acvmWasm)), initNoirC(fetch(noircWasm))]);
  const [program, input, vk] = await Promise.all([
    fetched('program.json').then((r) => r.json()),
    fetched('input.json').then((r) => r.json()),
    fetched('vk.bin').then((r) => r.arrayBuffer()).then((b) => new Uint8Array(b)),
  ]);

  stage('Computing the witness');
  let t = performance.now();
  const { witness } = await new Noir(program).execute(input);
  done(`Witness: ${secs(since(t))}`);

  for (const threads of modes) {
    stage(`Getting ready on ${threads === 1 ? 'one thread' : `${threads} threads`}`);
    t = performance.now();
    const api = await Barretenberg.new({ threads, srsSize: SRS_POINTS });
    const setup = since(t);
    stage(`Proving on ${threads === 1 ? 'one thread' : `${threads} threads`}`);
    t = performance.now();
    const proof = await new UltraHonkBackend(program.bytecode, api).generateProof(witness);
    const prove = since(t);
    stage('Checking the proof');
    const valid = await new UltraHonkVerifierBackend(api).verifyProof({ ...proof, verificationKey: vk });
    await api.destroy();
    done(`${threads === 1 ? '1 thread' : `${threads} threads`}: proof ${secs(prove)}, ${valid ? 'valid' : 'NOT VALID'} (setup ${secs(setup)})`);
  }
  if (modes.length === 1 && cores > 1) run.notes.add(`all cores not tried: the page is not cross-origin isolated${params.has('threads') ? ' (?threads=1)' : ''}`);
}

$('start').addEventListener('click', async () => {
  $('start').disabled = true;
  $('crash').hidden = true;
  $('result').hidden = true;
  $('status').hidden = false;
  $('step').textContent = '';
  const startedAt = Date.now();
  run = {
    notes: new Set(),
    lines: [],
    state: { startedAt, stage: 'starting', device },
    ticker: setInterval(() => { $('elapsed').textContent = `Running ${clock((Date.now() - startedAt) / 1000)}`; }, 1000),
  };
  keepAwake();
  let failure = null;
  try {
    await test();
  } catch (err) {
    failure = `FAILED while ${run.state.stage}: ${String((err && err.message) || err)}`;
  }
  clearInterval(run.ticker);
  wakeLock && wakeLock.release().catch(() => {});
  const notes = [...run.notes];
  const text = [
    `zkID PAN phone test (Noir), ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`,
    ...run.lines,
    ...(failure ? [`Result: ${failure}`] : []),
    `Device: ${device}`,
    ...(notes.length ? [`Notes: ${notes.join('; ')}`] : []),
  ].join('\n');
  store.del(RUN);
  store.set(LAST, text);
  $('result-text').textContent = text;
  $('result').hidden = false;
  $('status').hidden = true;
  $('start').disabled = false;
  $('start').textContent = 'Run again';
  run = null;
});

document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', async () => {
    const text = $(button.dataset.copy).textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = 'Copied';
    } catch {
      const range = document.createRange();
      range.selectNodeContents($(button.dataset.copy));
      getSelection().removeAllRanges();
      getSelection().addRange(range);
      button.textContent = 'Selected: copy it with your phone';
    }
  });
});

// Runs worker.js and shows its timings. The current stage is kept in
// localStorage, so if the tab runs out of memory and reloads, the next visit
// says where it stopped.
const $ = (id) => document.getElementById(id);
const KEY = 'zkid-bench-stage';

const storage = {
  get: () => { try { return localStorage.getItem(KEY); } catch { return null; } },
  set: (v) => { try { localStorage.setItem(KEY, v); } catch { /* private mode: no crash report */ } },
  clear: () => { try { localStorage.removeItem(KEY); } catch { /* ignore */ } },
};

const previous = storage.get();
if (previous) {
  $('previous').hidden = false;
  $('previous').textContent = `The last run did not finish. It stopped during: ${previous}. ` +
    'The tab most likely ran out of memory. Please include this line in what you send.';
}

function device() {
  return {
    userAgent: navigator.userAgent,
    cores: navigator.hardwareConcurrency ?? null,
    deviceMemoryGB: navigator.deviceMemory ?? null, // Chrome only, rounded
    secureContext: window.isSecureContext,
  };
}

function show(result) {
  $('result').hidden = false;
  $('copy').hidden = false;
  $('result').textContent = JSON.stringify(result, null, 2);
}

$('copy').onclick = () => navigator.clipboard?.writeText($('result').textContent);

$('run').onclick = () => {
  $('run').disabled = true;
  const started = performance.now();
  const singleThread = $('single').checked;
  const worker = new Worker(singleThread ? 'worker.js?threads=1' : 'worker.js');
  worker.onmessage = ({ data }) => {
    if (data.type === 'stage') {
      storage.set(`${data.name}${singleThread ? ' (single thread)' : ''}`);
      $('status').textContent = `${data.name}… (${Math.round((performance.now() - started) / 1000)} s so far)`;
      return;
    }
    storage.clear();
    const totalMs = Math.round(performance.now() - started);
    const jsHeapMB = performance.memory ? Math.round(performance.memory.usedJSHeapSize / 2 ** 20) : null;
    if (data.type === 'done') {
      $('status').textContent = data.report.stages.verify.valid ? 'Done: the proof verified.' : 'Done, but the proof did NOT verify.';
      show({ when: new Date().toISOString(), device: device(), singleThread, totalMs, mainThreadJsHeapMB: jsHeapMB, ...data.report });
    } else {
      $('status').textContent = `Failed: ${data.message}`;
      show({ when: new Date().toISOString(), device: device(), singleThread, totalMs, error: data.message });
    }
    worker.terminate();
    $('run').disabled = false;
  };
  worker.onerror = (e) => {
    $('status').textContent = `Worker error: ${e.message}`;
    show({ when: new Date().toISOString(), device: device(), error: e.message, stage: storage.get() });
    storage.clear();
    $('run').disabled = false;
  };
};

// zkID holder app. A website sends you here with ?request=<URL of its proof
// request>. You choose an image of your Aadhaar Secure QR, or the XML of your
// DigiLocker PAN Verification Record, among those the website accepts; this
// page reads it, checks the issuer's signature and the website's rules, shows
// exactly what the website will learn, proves on this device, and sends the
// website only the proof. The QR or record never leaves this page.
import { useEffect, useMemo, useState } from 'react';
import { fetchRequest, publicInputsFor } from './holder/request.js';
import { checkQr, inputFor, readQrImage, shown, trustedKeys } from './holder/qr.js';
import { checkPan, panInputFor, readPanFile, trustedPanKeys } from './holder/pan.js';
import { lowMemoryDevice, prove } from './holder/prove.js';
import { HolderError } from './holder/errors.js';

const describe = (err) => `${err.message}${err.code ? ` (${err.code})` : ''}`;
const days = (seconds) => (seconds % 86400 === 0 ? `${seconds / 86400} day${seconds === 86400 ? '' : 's'}` : `${Math.round(seconds / 3600)} hours`);
const hostOf = (origin) => new URL(origin).host;
const istHour = (date) =>
  `${date.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Asia/Kolkata' })}, ${date.toLocaleTimeString('en-IN', { hour: '2-digit', hour12: false, timeZone: 'Asia/Kolkata' })}:00 IST`;

const FIELDS = [
  ['gender', 'Gender'],
  ['pinCode', 'PIN code'],
  ['state', 'State'],
];

const CREDENTIALS = {
  aadhaar: { name: 'Aadhaar QR', what: 'QR' },
  pan: { name: 'PAN record (DigiLocker)', what: 'record' },
};

function Bar({ state, label }) {
  return (
    <header className="bar">
      <span className="logo">zkID</span>
      <span className="tag">{label}</span>
      <span className="led" data-state={state} aria-hidden="true" />
    </header>
  );
}

function Step({ n, title, children, testid }) {
  return (
    <section className="panel" data-testid={testid}>
      <h2>
        <span className="num">{n}</span>
        {title}
      </h2>
      {children}
    </section>
  );
}

// What the website asks for, as chips.
function Rules({ rules, documents }) {
  const chips = [];
  if (rules.age19) chips.push(['age', '19 or older']);
  for (const [field, label] of FIELDS) {
    if (rules[field]) chips.push([field, `${label}: ${rules[field].map(shown[field]).join(' / ')}`]);
  }
  if (!chips.length) chips.push(['none', `${documents.map((d) => CREDENTIALS[d].name).join(' or ')}, nothing more`]);
  return (
    <ul className="chips">
      {chips.map(([kind, text]) => (
        <li key={kind} className="chip" data-kind={kind}>
          {text}
        </li>
      ))}
    </ul>
  );
}

// Exactly what the proof will show the website: the values of the fields its
// rules name, and what every proof shows.
function Disclosure({ verifier, rules, checked }) {
  const pan = checked.kind === 'pan';
  const rows = [];
  if (rules.age19) rows.push(['19 or older', pan ? 'Yes, today' : 'Yes', 'age']);
  for (const [field, label] of FIELDS) {
    if (rules[field]) rows.push([label, shown[field](checked.disclosed[field]), field]);
  }
  const address = rules.pinCode || rules.state ? 'the rest of your address' : 'address';
  const hidden = pan
    ? ['name', 'date of birth', ...(rules.gender ? [] : ['gender']), 'PAN number']
    : ['name', 'date of birth', ...FIELDS.filter(([f]) => !rules[f]).map(([, l]) => (l === 'PIN code' ? l : l.toLowerCase())), address, 'photo', 'Aadhaar number'];
  return (
    <>
      <table className="readout" data-testid="disclosure">
        <tbody>
          {rows.map(([label, value, kind]) => (
            <tr key={label}>
              <th>{label}</th>
              <td>
                <span className="dot" data-kind={kind} />
                {value}
              </td>
            </tr>
          ))}
          <tr className="always">
            <th>{pan ? 'PAN verified by DigiLocker' : 'QR generated'}</th>
            <td>{istHour(pan ? checked.verifiedAt : checked.generatedAt)}</td>
          </tr>
          <tr className="always">
            <th>Signed with</th>
            <td>{checked.signer.label}</td>
          </tr>
          <tr className="always">
            <th>Your code here</th>
            <td>one per person on {verifier}, different on every other site</td>
          </tr>
        </tbody>
      </table>
      <p className="never">
        <span className="label">Never sent</span> your {hidden.join(', ')}, or the {pan ? 'record' : 'QR'} itself.
      </p>
      {rows.some(([, , kind]) => kind !== 'age') && (
        <p className="note">
          A rule on {pan ? 'gender' : 'gender, PIN code or state'} shows the website your value, not only that it passes:
          that is how the circuit works.
        </p>
      )}
    </>
  );
}

// Download parts, then proving: a segmented meter.
function Meter({ progress }) {
  if (!progress) return null;
  const segments = 24;
  const lit = progress.stage === 'download' ? Math.round((progress.done / progress.total) * segments) : segments;
  return (
    <div className="meter" data-stage={progress.stage} role="progressbar" aria-valuemin={0} aria-valuemax={segments} aria-valuenow={lit}>
      {Array.from({ length: segments }, (_, i) => (
        <span key={i} className={i < lit ? 'on' : ''} style={{ '--i': i }} />
      ))}
    </div>
  );
}

function Landing() {
  return (
    <>
      <Bar state="idle" label="Holder" />
      <main className="landing">
        <p className="kicker">Zero-knowledge Aadhaar</p>
        <h1>
          Prove one thing.
          <br />
          Show nothing else.
        </h1>
        <p className="lede">
          zkID proves to a website that your Aadhaar QR, or your PAN record from DigiLocker, meets its rules, such as 19
          or older, without sending it or anything in it. The proof is made on this device.
        </p>
        <ol className="how">
          <li>
            <span className="num">01</span>A website sends you here with its rules.
          </li>
          <li>
            <span className="num">02</span>You open a screenshot of the QR on your e-Aadhaar, or your PAN record's XML from
            DigiLocker. It never leaves this page.
          </li>
          <li>
            <span className="num">03</span>You see exactly what the website will learn, then prove and send.
          </li>
        </ol>
        <p className="note">
          Research prototype, built on Anon Aadhaar's circuit and zkID's PAN circuit. The project's threat model lists what
          it does and does not defend.
        </p>
      </main>
      <footer className="foot">Research prototype · Aadhaar and PAN circuits · proof made on this device</footer>
    </>
  );
}

export default function App() {
  const requestUrl = useMemo(() => new URLSearchParams(window.location.search).get('request'), []);
  const [served, setServed] = useState(null);
  const [checked, setChecked] = useState(null);
  const [status, setStatus] = useState('');
  const [progress, setProgress] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [singleThread, setSingleThread] = useState(lowMemoryDevice());
  const [answer, setAnswer] = useState(null);
  const [credential, setCredential] = useState(null); // 'aadhaar' or 'pan'

  useEffect(() => {
    if (!requestUrl) return;
    fetchRequest(requestUrl).then((accepted) => {
      setServed(accepted);
      if (accepted.request.documents.length === 1) setCredential(accepted.request.documents[0]);
    }, setError);
  }, [requestUrl]);

  if (!requestUrl) return <Landing />;

  const verifier = served?.request.verifierId;
  const rules = served?.request.rules;
  const documents = served?.request.documents ?? [];
  const led = error ? 'error' : answer ? (answer.ok ? 'ok' : 'error') : busy ? 'busy' : 'idle';

  function choose(next) {
    setCredential(next);
    setChecked(null);
    setError(null);
  }

  async function onFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setError(null);
    setChecked(null);
    setStatus(`Reading the ${CREDENTIALS[credential].what} on this device…`);
    try {
      if (credential === 'pan') {
        setChecked({ kind: 'pan', ...(await checkPan(await readPanFile(file), trustedPanKeys(), served.request)) });
      } else {
        setChecked({ kind: 'aadhaar', ...(await checkQr(await readQrImage(file), await trustedKeys(), served.request)) });
      }
      setStatus('');
    } catch (err) {
      setStatus('');
      setError(err);
    }
  }

  // The Aadhaar QR's proof, in a Web Worker.
  async function proveAadhaar(elapsed) {
    const input = inputFor(checked, await publicInputsFor(served.request), rules);
    const { proof, publicSignals } = await prove(input, {
      singleThread,
      onStage: ({ stage, done, total }) => {
        setProgress({ stage, done, total });
        setStatus(stage === 'download' ? `Downloading the circuit: part ${done} of ${total} (about 306 MB the first time)` : `Proving on this device: ${elapsed()} s`);
      },
    });
    return { document: 'aadhaar', proof, publicSignals };
  }

  // The PAN record's proof: its prover loads only now.
  async function provePanRecord(elapsed) {
    const input = panInputFor(checked, await publicInputsFor(served.request), served.request);
    setStatus('Loading the PAN prover…');
    const { panThreads, provePan } = await import('./holder/pan-prove.js');
    const threads = panThreads();
    return provePan(input, {
      onStage: (stage) => {
        if (stage === 'witness') {
          setProgress({ stage: 'download', done: 1, total: 3 });
          setStatus('Checking the record in the circuit…');
        } else if (stage === 'setup') {
          setProgress({ stage: 'download', done: 2, total: 3 });
          setStatus('Getting the prover ready (about 20 MB to download the first time)…');
        } else {
          setProgress({ stage: 'prove' });
          setStatus(`Proving on this device, on ${threads === 1 ? 'one thread' : `${threads} threads`}…`);
        }
      },
    });
  }

  async function onProve() {
    setBusy(true);
    setError(null);
    const started = performance.now();
    const elapsed = () => Math.round((performance.now() - started) / 1000);
    try {
      const result = checked.kind === 'pan' ? await provePanRecord(elapsed) : await proveAadhaar(elapsed);
      setStatus(`Proof made in ${elapsed()} s. Sending it to ${hostOf(verifier)}…`);
      const res = await fetch(served.responseUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(result),
        credentials: 'omit',
      });
      const answer = await res.json().catch(() => null);
      if (typeof answer?.ok !== 'boolean') {
        throw new HolderError('BAD_ANSWER', `${verifier} answered with HTTP ${res.status}, not a zkID result.`);
      }
      setAnswer(answer);
      setStatus('');
    } catch (err) {
      setStatus('');
      setError(err);
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  return (
    <>
      <Bar state={led} label="Holder · on this device" />
      <main>
        {!served && !error && <p className="status">Loading the request…</p>}
        {served && (
          <>
            <Step n="01" title="Request" testid="request">
              <p className="lead">
                <strong>{hostOf(verifier)}</strong> asks you to prove:
              </p>
              <Rules rules={rules} documents={documents} />
              <p className="meta">
                {verifier} · {documents.map((d) => CREDENTIALS[d].name).join(' or ')} · at most {days(served.request.maxAgeSeconds)} old
              </p>
            </Step>

            <Step n="02" title={credential ? `Your ${CREDENTIALS[credential].name}` : 'Your credential'}>
              {documents.length > 1 && (
                <div className="choice" role="group" aria-label="Credential">
                  {documents.map((d) => (
                    <button
                      key={d}
                      className={`key${credential === d ? ' key--primary' : ''}`}
                      aria-pressed={credential === d}
                      onClick={() => choose(d)}
                      disabled={busy || !!answer}
                      data-testid={`choose-${d}`}
                    >
                      {CREDENTIALS[d].name}
                    </button>
                  ))}
                </div>
              )}
              {credential === 'aadhaar' && (
                <>
                  <label className={`key key--file${busy || answer ? ' is-disabled' : ''}`}>
                    <input type="file" accept="image/*" onChange={onFile} disabled={busy || !!answer} aria-label="Aadhaar QR image" />
                    {checked ? 'Choose another image' : 'Open QR image'}
                  </label>
                  <p className="hint">
                    A screenshot of the QR on an e-Aadhaar downloaded from UIDAI in the last {days(served.request.maxAgeSeconds)}. It stays on
                    this device.
                  </p>
                </>
              )}
              {credential === 'pan' && (
                <>
                  <label className={`key key--file${busy || answer ? ' is-disabled' : ''}`}>
                    <input type="file" accept=".xml,application/xml,text/xml" onChange={onFile} disabled={busy || !!answer} aria-label="PAN record XML" />
                    {checked ? 'Choose another file' : 'Open PAN record (XML)'}
                  </label>
                  <p className="hint">
                    In DigiLocker, open your PAN Verification Record and download it as XML. DigiLocker must have verified it with the
                    Income Tax Department in the last {days(served.request.maxAgeSeconds)}. It stays on this device.
                  </p>
                </>
              )}
              {checked?.kind === 'aadhaar' && (
                <p className="ok" data-testid="qr-ok">
                  <span className="dot" data-kind="ok" />
                  Signed by {checked.signer.label} ({checked.signer.id}), generated {checked.generatedAt.toDateString()}.
                </p>
              )}
              {checked?.kind === 'pan' && (
                <p className="ok" data-testid="pan-ok">
                  <span className="dot" data-kind="ok" />
                  Signed by {checked.signer.label} ({checked.signer.id}); DigiLocker verified the PAN on {checked.verifiedAt.toDateString()}.
                </p>
              )}
            </Step>

            {checked && (
              <Step n="03" title={`What ${hostOf(verifier)} will see`}>
                <Disclosure verifier={hostOf(verifier)} rules={rules} checked={checked} />
              </Step>
            )}

            {checked && !answer && (
              <Step n="04" title="Prove">
                {checked.kind === 'aadhaar' && (
                  <label className="switch">
                    <input type="checkbox" checked={singleThread} onChange={(e) => setSingleThread(e.target.checked)} disabled={busy} />
                    <span className="track" aria-hidden="true" />
                    One thread: slower, about half the memory. Use it on a phone.
                  </label>
                )}
                <button className="key key--primary" onClick={onProve} disabled={busy}>
                  Prove and send to {hostOf(verifier)}
                </button>
                <Meter progress={progress} />
              </Step>
            )}
          </>
        )}
        {status && (
          <p className="status" aria-live="polite">
            {status}
          </p>
        )}
        {error && (
          <p className="alert" role="alert" data-testid="error">
            {describe(error)}
          </p>
        )}
        {answer && (
          <section className="screen" data-testid="answer" data-ok={answer.ok}>
            <p className="screen__label">{hostOf(verifier)} says</p>
            <h2>{answer.ok ? 'Accepted' : 'Refused'}</h2>
            <p>{answer.ok ? `The proof checked out${answer.account ? `: account #${String(answer.account).padStart(3, '0')}` : ''}.` : `${answer.code}. ${answer.detail ?? ''}`}</p>
            <a className="key key--light" href={served.returnUrl}>
              Back to {hostOf(verifier)}
            </a>
          </section>
        )}
      </main>
      <footer className="foot">Research prototype · Aadhaar and PAN circuits · proof made on this device</footer>
    </>
  );
}

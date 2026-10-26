// zkID holder app. A website sends you here with ?request=<URL of its proof
// request>. You choose an image of your Aadhaar Secure QR; this page reads it,
// checks UIDAI's signature, proves "19 or older" in a Web Worker, and sends the
// website only the proof. The QR never leaves this page.
import { useEffect, useMemo, useState } from 'react';
import { fetchRequest, publicInputsFor } from './holder/request.js';
import { checkQr, inputFor, readQrImage, trustedKeys } from './holder/qr.js';
import { lowMemoryDevice, prove } from './holder/prove.js';
import { HolderError } from './holder/errors.js';

const describe = (err) => `${err.message}${err.code ? ` (${err.code})` : ''}`;
const days = (seconds) => (seconds % 86400 === 0 ? `${seconds / 86400} day${seconds === 86400 ? '' : 's'}` : `${Math.round(seconds / 3600)} hours`);

function Disclosure({ verifier }) {
  return (
    <section>
      <h2>What {verifier} will learn</h2>
      <ul>
        <li>That a QR signed by UIDAI shows you were <strong>19 or older</strong> on the day the QR was generated.</li>
        <li>The hour your QR was generated, and which UIDAI key signed it.</li>
        <li>
          A code for your account on {verifier}. It is the same each time you prove to this website (it can change
          if your Aadhaar photo or address is updated) and different on every other website.
        </li>
      </ul>
      <h2>What it will not learn</h2>
      <p>Your name, date of birth, gender, address, Aadhaar number or photo.</p>
      <p>
        Your QR stays on this device: this page reads it here and sends only the proof. Anyone who has a copy of your
        QR could make the same proof, so keep your e-Aadhaar private.
      </p>
    </section>
  );
}

export default function App() {
  const requestUrl = useMemo(() => new URLSearchParams(window.location.search).get('request'), []);
  const [served, setServed] = useState(null);
  const [checked, setChecked] = useState(null);
  const [status, setStatus] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [singleThread, setSingleThread] = useState(lowMemoryDevice());
  const [answer, setAnswer] = useState(null);

  useEffect(() => {
    if (requestUrl) fetchRequest(requestUrl).then(setServed, setError);
  }, [requestUrl]);

  if (!requestUrl) {
    return (
      <main>
        <h1>zkID</h1>
        <p>
          Prove to a website that you are 19 or older, using your Aadhaar Secure QR, without showing it anything else.
          A website that uses zkID opens this page with its request.
        </p>
        <p className="note">Research prototype. Built on Anon Aadhaar's circuit; see the project's threat model for what it does and does not defend.</p>
      </main>
    );
  }

  const verifier = served?.request.verifierId;

  async function onFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setError(null);
    setChecked(null);
    setStatus('Reading the QR on this device…');
    try {
      const text = await readQrImage(file);
      setChecked(await checkQr(text, await trustedKeys(), served.request));
      setStatus('');
    } catch (err) {
      setStatus('');
      setError(err);
    }
  }

  async function onProve() {
    setBusy(true);
    setError(null);
    const started = performance.now();
    try {
      const input = inputFor(checked, await publicInputsFor(served.request));
      const result = await prove(input, {
        singleThread,
        onStage: ({ stage, done, total }) =>
          setStatus(stage === 'download' ? `Downloading the circuit (${done} of ${total}; about 306 MB the first time)…` : `Proving on this device… (started ${Math.round((performance.now() - started) / 1000)} s ago)`),
      });
      setStatus(`Proof made in ${Math.round((performance.now() - started) / 1000)} s. Sending it to ${verifier}…`);
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
    }
  }

  return (
    <main>
      <h1>zkID</h1>
      {!served && !error && <p>Loading the request…</p>}
      {served && (
        <>
          <p>
            <strong>{verifier}</strong> asks you to prove that you are 19 or older. It accepts a QR generated in the
            last {days(served.request.maxAgeSeconds)}.
          </p>
          <Disclosure verifier={verifier} />
          <section>
            <h2>Your Aadhaar QR</h2>
            <p>Choose a screenshot of the QR on your e-Aadhaar (downloaded from UIDAI).</p>
            <input type="file" accept="image/*" onChange={onFile} disabled={busy || !!answer} aria-label="Aadhaar QR image" />
            {checked && (
              <p className="ok" data-testid="qr-ok">
                Signed by {checked.signer.label} ({checked.signer.id}), generated on {checked.generatedAt.toDateString()}.
              </p>
            )}
          </section>
          {checked && !answer && (
            <section>
              <label>
                <input type="checkbox" checked={singleThread} onChange={(e) => setSingleThread(e.target.checked)} disabled={busy} /> One
                thread: slower, but needs about half the memory. Use it on a phone; a phone may still run out of memory.
              </label>
              <p>
                <button onClick={onProve} disabled={busy}>
                  Prove and send to {verifier}
                </button>
              </p>
            </section>
          )}
        </>
      )}
      {status && <p aria-live="polite">{status}</p>}
      {error && (
        <p className="error" role="alert" data-testid="error">
          {describe(error)}
        </p>
      )}
      {answer && (
        <section data-testid="answer">
          <h2>{answer.ok ? 'Accepted' : 'Refused'}</h2>
          <p>{answer.ok ? `${verifier} accepted the proof.` : `${verifier} refused it: ${answer.code}. ${answer.detail ?? ''}`}</p>
          <p>
            <a href={served.returnUrl}>Back to {verifier}</a>
          </p>
        </section>
      )}
    </main>
  );
}

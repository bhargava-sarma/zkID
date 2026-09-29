import { useEffect, useRef, useState } from 'react';
import { checkProofCode } from '../verify/checkProofCode.js';
import { codeFromText } from '../verify/proofCode.js';

function cameraMessage(err) {
  if (err.name === 'NotAllowedError') return 'Camera permission was denied. Upload a photo of the QR code instead.';
  if (err.name === 'NotFoundError' || err.name === 'OverconstrainedError') {
    return 'No camera was found. Upload a photo of the QR code instead.';
  }
  return err.message || 'The camera could not be started.';
}

// Reads frames from the camera until one contains a QR code.
function CameraScanner({ onText, onError }) {
  const videoRef = useRef(null);

  useEffect(() => {
    let stopped = false;
    let stream = null;
    let frame = 0;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw new Error('The camera needs a secure (https) page.');
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
        if (stopped) return;
        const video = videoRef.current;
        video.srcObject = stream;
        await video.play();
        const jsQR = (await import('jsqr')).default;
        const tick = () => {
          if (stopped) return;
          if (video.readyState >= video.HAVE_ENOUGH_DATA && video.videoWidth > 0) {
            const scale = Math.min(1, 800 / video.videoWidth);
            canvas.width = Math.round(video.videoWidth * scale);
            canvas.height = Math.round(video.videoHeight * scale);
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const found = jsQR(data, width, height, { inversionAttempts: 'dontInvert' });
            if (found) {
              onText(found.data);
              return;
            }
          }
          frame = requestAnimationFrame(tick);
        };
        tick();
      } catch (err) {
        if (!stopped) onError(cameraMessage(err));
      }
    })();

    return () => {
      stopped = true;
      cancelAnimationFrame(frame);
      stream?.getTracks().forEach((track) => track.stop());
    };
  }, []);

  return <video ref={videoRef} className="camera-view" muted playsInline />;
}

async function readQrFromImage(file) {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement('canvas');
  canvas.width = Math.round(bitmap.width * scale);
  canvas.height = Math.round(bitmap.height * scale);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const jsQR = (await import('jsqr')).default;
  return jsQR(data, width, height, { inversionAttempts: 'attemptBoth' })?.data ?? null;
}

function rejectionReason(result) {
  if (result.unreadable) return 'This is not a readable zkID proof code.';
  if (!result.issuer) return "It was signed by an issuer this verifier doesn't trust.";
  if (!result.proofValid) return "The proof doesn't verify: it was altered, or wasn't made from a credential this issuer signed.";
  return "The proof doesn't show the holder is 18 or older today.";
}

function Check({ ok, title, detail }) {
  const status = ok === null ? 'pending' : ok ? 'complete' : 'failed';
  return (
    <div className={`verify-check status-${status}`}>
      <span className="verify-check-icon">{ok === null ? '○' : ok ? '✓' : '✕'}</span>
      <div>
        <div className="verify-check-title">{title}</div>
        <div className="verify-check-detail">{detail}</div>
      </div>
    </div>
  );
}

// Relying-party page: scan or upload a zkID proof QR code and check it here.
// Nothing is sent to a server; the code arrives in the URL fragment.
function VerifyPage({ code }) {
  const [mode, setMode] = useState('idle'); // idle | camera | checking | result
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const fileRef = useRef(null);

  useEffect(() => {
    if (!code) {
      setMode('idle');
      setResult(null);
      return undefined;
    }
    let cancelled = false;
    setMode('checking');
    setError(null);
    checkProofCode(code)
      .then((r) => {
        if (cancelled) return;
        setResult(r);
        setMode('result');
      })
      .catch((err) => {
        if (cancelled) return;
        setError(`The proof could not be checked: ${err.message}`);
        setMode('idle');
      });
    return () => {
      cancelled = true;
    };
  }, [code]);

  const open = (text) => {
    const found = codeFromText(text);
    if (!found) {
      setError('That QR code is not a zkID proof.');
      setMode('idle');
      return;
    }
    window.location.hash = `#/verify?p=${found}`;
  };

  const onFile = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setError(null);
    try {
      const text = await readQrFromImage(file);
      if (text) open(text);
      else setError('No QR code was found in that image. Try a sharper, closer photo.');
    } catch {
      setError('That file could not be read as an image.');
    }
  };

  if (mode === 'checking') {
    return (
      <div className="card">
        <h2 className="card-title">Checking Proof</h2>
        <div className="loading-container">
          <div className="spinner" />
          <div className="loading-text">Verifying the Groth16 proof in this browser...</div>
        </div>
      </div>
    );
  }

  if (mode === 'result' && result) {
    return (
      <div className="card">
        <h2 className="card-title">Proof Check</h2>
        <div className={`verify-verdict ${result.accepted ? 'accepted' : 'rejected'}`}>
          <div className="verify-verdict-icon">{result.accepted ? '✓' : '✕'}</div>
          <div className="verify-verdict-title">{result.accepted ? 'Accepted: 18 or older' : 'Rejected'}</div>
          <div className="verify-verdict-reason">
            {result.accepted
              ? 'A trusted issuer signed a credential whose holder is 18 or older today.'
              : rejectionReason(result)}
          </div>
        </div>

        {!result.unreadable && (
          <div className="verify-checks">
            <Check
              ok={Boolean(result.issuer)}
              title="Issuer"
              detail={result.issuer ? `${result.issuer} (key ${result.keyId})` : `Key ${result.keyId} is not on this verifier's trusted list`}
            />
            <Check
              ok={result.proofValid}
              title="Proof"
              detail={
                result.proofValid === null
                  ? 'Not checked: there is no trusted key to check it against'
                  : result.proofValid
                  ? "Valid Groth16 proof under the issuer's key"
                  : 'Invalid'
              }
            />
            <Check
              ok={result.ageOk}
              title="18 or older today"
              detail={`Born on or before ${result.bornOnOrBefore}. Today's cutoff is ${result.cutoff}.`}
            />
          </div>
        )}

        <div className="privacy-note">
          <span className="privacy-note-icon">ⓘ</span>
          <div className="privacy-note-text">
            Checked in this browser. The code reveals only the issuer and the cutoff date. It isn't tied to this
            check or to the person showing it: a copy of the same code gives the same result.
          </div>
        </div>

        <div className="step-actions">
          <button className="btn btn-primary btn-full" onClick={() => (window.location.hash = '#/verify')}>
            Check another proof
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <h2 className="card-title">Verify a Proof</h2>
      <p className="card-description">
        Scan the QR code from someone's zkID signed credential proof. The proof is checked in this browser, and you
        learn only whether a trusted issuer vouches that its holder is 18 or older.
      </p>

      {mode === 'camera' ? (
        <>
          <CameraScanner
            onText={open}
            onError={(message) => {
              setError(message);
              setMode('idle');
            }}
          />
          <div className="step-actions">
            <button className="btn btn-outline btn-full" onClick={() => setMode('idle')}>
              Stop camera
            </button>
          </div>
        </>
      ) : (
        <div className="verify-actions">
          <button
            className="btn btn-primary"
            onClick={() => {
              setError(null);
              setMode('camera');
            }}
          >
            Scan with camera
          </button>
          <button className="btn btn-outline" onClick={() => fileRef.current?.click()}>
            Upload QR image
          </button>
          <input ref={fileRef} type="file" accept="image/*" className="upload-input" onChange={onFile} />
        </div>
      )}

      {error && <div className="error-message">{error}</div>}
    </div>
  );
}

export default VerifyPage;

import { useState } from 'react';
import { encodeProofCode, verifierLink } from '../verify/proofCode.js';

// A signed proof as a QR code. It opens the verifier page, which checks the
// proof in the browser: no server or chain call is needed.
function ProofQR({ proof, publicSignals }) {
  const [qr, setQr] = useState(null);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  const show = async () => {
    setError(null);
    try {
      const link = verifierLink(await encodeProofCode(proof, publicSignals));
      const QRCode = (await import('qrcode')).default;
      const image = await QRCode.toDataURL(link, { errorCorrectionLevel: 'M', margin: 2, width: 480 });
      setQr({ link, image });
    } catch (err) {
      setError(`Could not make a QR code: ${err.message}`);
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(qr.link);
      setCopied(true);
    } catch {
      setError('Copying was blocked by the browser. Use "Open verifier" and copy the address instead.');
    }
  };

  if (!qr) {
    return (
      <div className="qr-show">
        <button className="btn btn-outline btn-full" onClick={show}>
          Show as QR code
        </button>
        {error && <div className="error-message">{error}</div>}
      </div>
    );
  }

  return (
    <div className="qr-section">
      <div className="onchain-header">
        <span className="onchain-header-icon">▦</span>
        <span className="onchain-header-title">Proof QR Code</span>
      </div>
      <div className="qr-body">
        <img className="qr-image" src={qr.image} alt="QR code of this proof" />
        <div className="qr-text">
          <p>
            Scan it with a phone camera to open the zkID verifier, which checks the proof in the browser. The code
            holds only the issuer's key ID, the cutoff date and the proof: no name, date of birth or Aadhaar number.
          </p>
          <p className="qr-warning">
            Anyone with a copy or a screenshot gets the same result, so show it only to the party checking you.
          </p>
          <div className="qr-actions">
            <button className="btn btn-outline" onClick={copy}>
              {copied ? 'Link copied' : 'Copy link'}
            </button>
            <a className="btn btn-outline" href={qr.link} target="_blank" rel="noopener noreferrer">
              Open verifier ↗
            </a>
          </div>
          {error && <div className="error-message">{error}</div>}
        </div>
      </div>
    </div>
  );
}

export default ProofQR;

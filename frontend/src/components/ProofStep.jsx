import { useState, useEffect } from 'react';
import axios from 'axios';
import { verifyOnChain } from '../contracts/onChainVerify';
import { hasVerifier, CHAIN } from '../contracts/contractConfig';

const PROOF_STAGES = [
  'Preparing circuit inputs...',
  'Computing witness...',
  'Generating Groth16 proof...',
  'Verifying proof...',
];

const SIGNED_STAGES = [
  'Reading the document...',
  'Signing the credential (RSA-2048)...',
  'Proving signature + age in one circuit...',
];

const TABS = [
  { key: 'signed', label: 'Signed Credential' },
  { key: 'age', label: 'Age Proof' },
  { key: 'name', label: 'Name Proof' },
  { key: 'gender', label: 'Gender Proof' },
];

const UPLOADED = 'uploaded';

const SIGNED_SCENARIOS = [
  { key: 'valid', label: 'Valid adult' },
  { key: 'underage', label: 'Underage' },
  { key: 'ocr_fail', label: 'Unreadable' },
  { key: 'gender_missing', label: 'No gender' },
  { key: 'dob_garbled', label: 'Garbled DOB' },
  { key: 'invalid_date', label: 'DOB 31 Feb' },
  { key: 'malformed_name', label: 'Quote in name' },
  { key: 'long_name', label: 'Name too long' },
];

const FAILURE_TITLES = {
  CREDENTIAL_UNPROCESSABLE: 'Retake the photo',
  AGE_REQUIREMENT_NOT_MET: 'Not eligible',
  PROVING_UNAVAILABLE: 'Verification unavailable',
};

const STAGE_LABELS = {
  upload_received: 'Input received',
  ocr_started: 'Reading document',
  ocr_complete: 'Fields extracted',
  credential_signing: 'Signing credential',
  credential_signed: 'Credential signed',
  proof_started: 'Proving',
  proof_complete: 'Proof generated',
  error: 'Stopped',
};

const HIDDEN_FIELDS = {
  signed: ['Date of Birth', 'Name', 'Gender'],
  age: ['Date of Birth'],
  name: ['Actual Name'],
  gender: ['Actual Gender Code'],
};

// Server-side pipeline stages. A "running" stage is shown only where the pipeline stopped.
function StageTrace({ stages }) {
  const visible = stages.filter((s, i) => s.status !== 'running' || stages[i + 1]?.status === 'failed');
  return (
    <div className="pipeline-status stage-trace">
      {visible.map((stage, index) => (
        <div key={index} className={`pipeline-status-item status-${stage.status}`}>
          <span className="status-icon">
            {stage.status === 'complete' ? '✓' : stage.status === 'failed' ? '✕' : '●'}
          </span>
          <span className="status-label">{STAGE_LABELS[stage.name] || stage.name}</span>
          {stage.detail && <span className="status-detail" title={stage.detail}>{stage.detail}</span>}
        </div>
      ))}
    </div>
  );
}

const GENDER_OPTIONS = [
  { code: 1, label: 'Male' },
  { code: 2, label: 'Female' },
  { code: 3, label: 'Other' },
];

function ProofStep({ userId, userName, source, onStartOver }) {
  const [activeTab, setActiveTab] = useState('signed');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [results, setResults] = useState({ signed: null, age: null, name: null, gender: null });
  const [currentStage, setCurrentStage] = useState(0);

  const [signedSource, setSignedSource] = useState(source?.file ? UPLOADED : source?.scenario || 'valid');
  const [signedFailure, setSignedFailure] = useState(null);

  const [claimedName, setClaimedName] = useState(userName || '');

  const [claimedGender, setClaimedGender] = useState(1);

  const [proofOpen, setProofOpen] = useState(false);
  const [signalsOpen, setSignalsOpen] = useState(false);

  const [onChainResults, setOnChainResults] = useState({});
  const [onChainLoading, setOnChainLoading] = useState({});

  const loadingStages = activeTab === 'signed' ? SIGNED_STAGES : PROOF_STAGES;

  useEffect(() => {
    if (!loading) return;
    setCurrentStage(0);
    const interval = setInterval(() => {
      setCurrentStage((prev) => (prev < loadingStages.length - 1 ? prev + 1 : prev));
    }, 800);
    return () => clearInterval(interval);
  }, [loading]);

  useEffect(() => {
    setProofOpen(false);
    setSignalsOpen(false);
    setError(null);
    setSignedFailure(null);
  }, [activeTab]);

  const triggerOnChainVerification = async (proofData, proofType) => {
    if (!hasVerifier(proofType)) return;
    if (!proofData.isValid || !proofData.proof || !proofData.publicSignals) return;

    setOnChainLoading((prev) => ({ ...prev, [proofType]: true }));
    try {
      const result = await verifyOnChain(proofData.proof, proofData.publicSignals, proofType);
      setOnChainResults((prev) => ({ ...prev, [proofType]: result }));
    } catch (err) {
      setOnChainResults((prev) => ({
        ...prev,
        [proofType]: { onChainValid: false, contractAddress: null, error: err.message },
      }));
    } finally {
      setOnChainLoading((prev) => ({ ...prev, [proofType]: false }));
    }
  };

  const handleGenerateSigned = async () => {
    setLoading(true);
    setSignedFailure(null);
    setOnChainResults((prev) => ({ ...prev, signed: null }));
    try {
      let res;
      if (signedSource === UPLOADED) {
        const formData = new FormData();
        formData.append('image', source.file);
        res = await axios.post('/api/signed-proof', formData);
      } else {
        res = await axios.post('/api/signed-proof', { scenario: signedSource });
      }
      setResults((prev) => ({ ...prev, signed: res.data }));
      triggerOnChainVerification(res.data, 'signed');
    } catch (err) {
      setSignedFailure(err.response?.data || { error: 'Server unreachable.' });
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateAge = async () => {
    setLoading(true);
    setError(null);
    setOnChainResults((prev) => ({ ...prev, age: null }));
    try {
      const res = await axios.post('/api/generate-proof', { userId });
      setResults((prev) => ({ ...prev, age: res.data }));
      triggerOnChainVerification(res.data, 'age');
    } catch (err) {
      setError(err.response?.data?.error || 'Server unreachable.');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateName = async () => {
    if (!claimedName.trim()) {
      setError('Please enter a name to verify against.');
      return;
    }
    setLoading(true);
    setError(null);
    setOnChainResults((prev) => ({ ...prev, name: null }));
    try {
      const res = await axios.post('/api/generate-name-proof', { userId, claimedName: claimedName.trim() });
      setResults((prev) => ({ ...prev, name: res.data }));
      triggerOnChainVerification(res.data, 'name');
    } catch (err) {
      setError(err.response?.data?.error || 'Server unreachable.');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateGender = async () => {
    setLoading(true);
    setError(null);
    setOnChainResults((prev) => ({ ...prev, gender: null }));
    try {
      const res = await axios.post('/api/generate-gender-proof', { userId, claimedGender });
      setResults((prev) => ({ ...prev, gender: res.data }));
      triggerOnChainVerification(res.data, 'gender');
    } catch (err) {
      setError(err.response?.data?.error || 'Server unreachable.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    const tabLabel = TABS.find((t) => t.key === activeTab)?.label || 'Proof';
    return (
      <div className="card">
        <h2 className="card-title">Generating {tabLabel}</h2>
        <p className="card-description">
          {activeTab === 'signed'
            ? 'Verifying the issuer signature and the age check in one 256,574-constraint circuit. This takes about 4 seconds.'
            : 'Running the Groth16 zk-SNARK circuit. This may take a few seconds.'}
        </p>
        <div className="loading-container">
          <div className="spinner" />
          <div className="pipeline-status">
            {loadingStages.map((stage, index) => (
              <div
                key={index}
                className={`pipeline-status-item ${
                  index < currentStage ? 'status-complete' :
                  index === currentStage ? 'status-running' : 'status-pending'
                }`}
                style={{ animationDelay: `${index * 0.1}s` }}
              >
                <span className="status-icon">
                  {index < currentStage ? '✓' : index === currentStage ? '●' : '○'}
                </span>
                <span className="status-label">{stage}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const currentResult = results[activeTab];
  const currentOnChain = onChainResults[activeTab] || null;
  const currentOnChainLoading = onChainLoading[activeTab] || false;

  return (
    <div className="card">
      <h2 className="card-title">Zero-Knowledge Proofs</h2>
      <p className="card-description">
        Generate cryptographic proofs for different attributes without revealing private data.
        Each proof uses a separate Groth16 zk-SNARK circuit.
      </p>

      <div className="proof-tabs">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            className={`proof-tab ${activeTab === tab.key ? 'active' : ''} ${results[tab.key] ? 'has-result' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="proof-tab-content" key={activeTab}>
        {activeTab === 'signed' && !currentResult && (
          <>
            <p className="card-description">
              The issuer signs the credential, then a single circuit proves the signature is valid and the
              date of birth inside it is 18+. The proof can only attest to what the issuer signed.
            </p>
            <label className="name-input-label">Credential source</label>
            <div className="option-grid">
              {[...(source?.file ? [{ key: UPLOADED, label: 'Uploaded image' }] : []), ...SIGNED_SCENARIOS].map((opt) => (
                <button
                  key={opt.key}
                  className={`option-button ${signedSource === opt.key ? 'selected' : ''}`}
                  onClick={() => setSignedSource(opt.key)}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            <div className="step-actions">
              <button className="btn btn-primary btn-full" onClick={handleGenerateSigned}>
                Generate Signed Credential Proof
              </button>
            </div>
            {signedFailure && (
              <>
                <div className="proof-failed">
                  <div className="proof-failed-icon">{signedFailure.retryable ? '↻' : '✕'}</div>
                  <div className="proof-failed-title">{FAILURE_TITLES[signedFailure.code] || 'Proof Failed'}</div>
                  <div className="proof-failed-message">{signedFailure.error}</div>
                  {signedFailure.code && (
                    <div className="proof-failed-code">
                      {signedFailure.code} · {signedFailure.reason} · {signedFailure.retryable ? 'retryable' : 'not retryable'}
                    </div>
                  )}
                </div>
                {signedFailure.stages && <StageTrace stages={signedFailure.stages} />}
              </>
            )}
          </>
        )}

        {activeTab === 'age' && !currentResult && (
          <>
            <p className="card-description">
              Prove that the user is ≥18 years old without revealing their date of birth.
            </p>
            {error && <div className="error-message">{error}</div>}
            <div className="step-actions">
              <button className="btn btn-primary btn-full" onClick={handleGenerateAge}>
                Generate Age Proof
              </button>
            </div>
          </>
        )}

        {activeTab === 'name' && !currentResult && (
          <>
            <p className="card-description">
              Prove that the user's name matches a claimed identity without revealing the raw name in the proof.
              The circuit compares SHA-256 hashes.
            </p>
            <div className="name-input-group">
              <label className="name-input-label">Name to verify against</label>
              <input
                type="text"
                className="name-input"
                value={claimedName}
                onChange={(e) => setClaimedName(e.target.value)}
                placeholder="Enter the name to check..."
              />
            </div>
            {error && <div className="error-message">{error}</div>}
            <div className="step-actions">
              <button className="btn btn-primary btn-full" onClick={handleGenerateName} disabled={!claimedName.trim()}>
                Generate Name Proof
              </button>
            </div>
          </>
        )}

        {activeTab === 'gender' && !currentResult && (
          <>
            <p className="card-description">
              Prove that the user's gender matches a claimed value without exposing it in the proof.
            </p>
            <div className="option-group">
              {GENDER_OPTIONS.map((opt) => (
                <button
                  key={opt.code}
                  className={`option-button ${claimedGender === opt.code ? 'selected' : ''}`}
                  onClick={() => setClaimedGender(opt.code)}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            {error && <div className="error-message">{error}</div>}
            <div className="step-actions">
              <button className="btn btn-primary btn-full" onClick={handleGenerateGender}>
                Generate Gender Proof
              </button>
            </div>
          </>
        )}

        {error && !currentResult && activeTab === 'age' && (
          <div className="proof-failed">
            <div className="proof-failed-icon">✕</div>
            <div className="proof-failed-title">Proof Failed</div>
            <div className="proof-failed-message">{error}</div>
          </div>
        )}

        {currentResult && (
          <>
            {(currentResult.proofDuration || currentResult.verificationDuration) && (
              <div className="proof-timing">
                <div className="proof-timing-item">
                  <div className="proof-timing-label">Proof Generation</div>
                  <div className="proof-timing-value">
                    {currentResult.proofDuration || '—'}
                    <span className="proof-timing-unit">ms</span>
                  </div>
                </div>
                <div className="proof-timing-item">
                  <div className="proof-timing-label">Verification</div>
                  <div className="proof-timing-value">
                    {currentResult.verificationDuration || '—'}
                    <span className="proof-timing-unit">ms</span>
                  </div>
                </div>
              </div>
            )}

            <div className="privacy-note">
              <span className="privacy-note-icon">🔒</span>
              <div className="privacy-note-text">
                {activeTab === 'signed' && (
                  <><strong>Name, date of birth, Aadhaar number and gender were never exposed.</strong> The proof shows the issuer signed this credential and its holder is ≥18.</>
                )}
                {activeTab === 'age' && (
                  <><strong>Date of birth was never exposed.</strong> Only the fact that the user is ≥18 was proven.</>
                )}
                {activeTab === 'name' && (
                  <><strong>Raw name was never exposed.</strong> Only the hash match was proven — the verifier cannot learn the actual name from the proof.</>
                )}
                {activeTab === 'gender' && (
                  <><strong>Gender was never exposed in the proof.</strong> Only the match against the claimed value was proven cryptographically.</>
                )}
              </div>
            </div>

            <div className="proof-panels">
              <div className="proof-panel">
                <div className="proof-panel-title">What Verifier Sees</div>
                <div className={`verified-status ${currentResult.isValid ? 'valid' : 'invalid'}`}>
                  {currentResult.isValid ? '● VERIFIED' : '● FAILED'}
                </div>
                <div className="proof-attribute">
                  <div className="proof-attribute-label">Result</div>
                  <div className="proof-attribute-value">{currentResult.message}</div>
                </div>

                {activeTab === 'signed' && (
                  <>
                    <div className="proof-attribute">
                      <div className="proof-attribute-label">Threshold date (public signal)</div>
                      <div className="proof-attribute-value">{currentResult.thresholdDate || '—'}</div>
                    </div>
                    <div className="proof-attribute">
                      <div className="proof-attribute-label">Issuer key (public signal)</div>
                      <div className="proof-attribute-value">RSA-2048 modulus</div>
                    </div>
                  </>
                )}

                {activeTab === 'age' && (
                  <>
                    <div className="proof-attribute">
                      <div className="proof-attribute-label">
                        Threshold date (public signal)
                      </div>
                      <div className="proof-attribute-value">
                        {currentResult.thresholdDate || '—'}
                      </div>
                    </div>
                    <div className="proof-attribute">
                      <div className="proof-attribute-label">
                        Derived from (not a public signal)
                      </div>
                      <div className="proof-attribute-value">
                        {currentResult.todayDate || '—'}
                        {currentResult.minimumAgeYears
                          ? ` − ${currentResult.minimumAgeYears}y`
                          : ''}
                      </div>
                    </div>
                  </>
                )}

                {activeTab === 'name' && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Claimed Name</div>
                    <div className="proof-attribute-value">{currentResult.claimedName || '—'}</div>
                  </div>
                )}

                {activeTab === 'gender' && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Claimed Gender</div>
                    <div className="proof-attribute-value">{currentResult.claimedGenderLabel || '—'}</div>
                  </div>
                )}
              </div>

              <div className="proof-panel">
                <div className="proof-panel-title">What Is Hidden</div>
                {HIDDEN_FIELDS[activeTab].map((field) => (
                  <div className="proof-attribute" key={field}>
                    <div className="proof-attribute-label">{field}</div>
                    <div className="redacted-block">████████████</div>
                  </div>
                ))}
                <div className="proof-attribute">
                  <div className="proof-attribute-label">Aadhaar Number</div>
                  <div className="redacted-block">████████████</div>
                </div>
                <div className="hidden-note">
                  Private circuit inputs. Not present in proof or public signals.
                </div>
              </div>
            </div>

            {hasVerifier(activeTab) && currentResult.isValid && (
              <div className="onchain-section">
                <div className="onchain-header">
                  <span className="onchain-header-icon">⛓</span>
                  <span className="onchain-header-title">On-Chain Verification</span>
                </div>

                {currentOnChainLoading && (
                  <div className="onchain-body onchain-loading">
                    <div className="spinner spinner-small" />
                    <span className="onchain-loading-text">
                      Verifying proof on {CHAIN.name}...
                    </span>
                  </div>
                )}

                {!currentOnChainLoading && currentOnChain && currentOnChain.error === null && currentOnChain.onChainValid && (
                  <div className="onchain-body onchain-success">
                    <span className="onchain-badge-icon">✓</span>
                    <div className="onchain-badge-content">
                      <div className="onchain-badge-title">Verified on {CHAIN.name}</div>
                      <a
                        className="onchain-contract-link"
                        href={`${CHAIN.explorer}/address/${currentOnChain.contractAddress}`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {currentOnChain.contractAddress}
                        <span className="onchain-link-arrow">↗</span>
                      </a>
                    </div>
                  </div>
                )}

                {!currentOnChainLoading && currentOnChain && currentOnChain.error === null && !currentOnChain.onChainValid && (
                  <div className="onchain-body onchain-fail">
                    <span className="onchain-badge-icon">✕</span>
                    <div className="onchain-badge-content">
                      <div className="onchain-badge-title">On-chain verification returned false</div>
                      {currentOnChain.contractAddress && (
                        <a
                          className="onchain-contract-link"
                          href={`${CHAIN.explorer}/address/${currentOnChain.contractAddress}`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          {currentOnChain.contractAddress}
                          <span className="onchain-link-arrow">↗</span>
                        </a>
                      )}
                    </div>
                  </div>
                )}

                {!currentOnChainLoading && currentOnChain && currentOnChain.error !== null && (
                  <div className="onchain-body onchain-error">
                    <span className="onchain-badge-icon">⚠</span>
                    <div className="onchain-badge-content">
                      <div className="onchain-badge-title">On-chain check failed</div>
                      <div className="onchain-error-detail">{currentOnChain.error}</div>
                    </div>
                  </div>
                )}

                {!currentOnChainLoading && !currentOnChain && (
                  <div className="onchain-body onchain-loading">
                    <div className="spinner spinner-small" />
                    <span className="onchain-loading-text">
                      Initializing on-chain verification...
                    </span>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'signed' && (
              <>
                <StageTrace stages={currentResult.stages} />
                <div className="step-actions">
                  <button
                    className="btn btn-outline btn-full"
                    onClick={() => {
                      setResults((prev) => ({ ...prev, signed: null }));
                      setOnChainResults((prev) => ({ ...prev, signed: null }));
                    }}
                  >
                    Try another credential
                  </button>
                </div>
              </>
            )}

            <div className="collapsible">
              <div className="collapsible-header" onClick={() => setProofOpen(!proofOpen)}>
                <span className="collapsible-title">Raw ZK Proof (Groth16)</span>
                <span className="collapsible-toggle">{proofOpen ? '−' : '+'}</span>
              </div>
              <div className={`collapsible-body ${proofOpen ? 'open' : ''}`}>
                <pre className="code-block">
                  {JSON.stringify(currentResult.proof, null, 2)}
                </pre>
              </div>
            </div>

            <div className="collapsible">
              <div className="collapsible-header" onClick={() => setSignalsOpen(!signalsOpen)}>
                <span className="collapsible-title">Public Signals</span>
                <span className="collapsible-toggle">{signalsOpen ? '−' : '+'}</span>
              </div>
              <div className={`collapsible-body ${signalsOpen ? 'open' : ''}`}>
                <pre className="code-block">
                  {JSON.stringify(currentResult.publicSignals, null, 2)}
                </pre>
              </div>
            </div>
          </>
        )}
      </div>

      {onStartOver && (
        <div className="restart-btn">
          <button className="btn btn-outline" onClick={onStartOver}>
            ← Start Over
          </button>
        </div>
      )}
    </div>
  );
}

export default ProofStep;

import { useState, useEffect } from 'react';
import axios from 'axios';
import { verifyOnChain } from '../contracts/onChainVerify';

const PROOF_STAGES = [
  'Preparing circuit inputs...',
  'Computing witness...',
  'Generating Groth16 proof...',
  'Verifying proof...',
];

const TABS = [
  { key: 'age', label: 'Age Proof' },
  { key: 'name', label: 'Name Proof' },
  { key: 'gender', label: 'Gender Proof' },
];

const GENDER_OPTIONS = [
  { code: 1, label: 'Male' },
  { code: 2, label: 'Female' },
  { code: 3, label: 'Other' },
];

function ProofStep({ userId, userName, onProofComplete, onStartOver }) {
  const [activeTab, setActiveTab] = useState('age');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [results, setResults] = useState({ age: null, name: null, gender: null });
  const [currentStage, setCurrentStage] = useState(0);

  // Name proof inputs
  const [claimedName, setClaimedName] = useState(userName || '');

  // Gender proof inputs
  const [claimedGender, setClaimedGender] = useState(1);

  // Collapsible state
  const [proofOpen, setProofOpen] = useState(false);
  const [signalsOpen, setSignalsOpen] = useState(false);

  // On-chain verification state
  const [onChainResults, setOnChainResults] = useState({ age: null, name: null });
  const [onChainLoading, setOnChainLoading] = useState({ age: false, name: false });

  // Animate proof stages during loading
  useEffect(() => {
    if (!loading) return;
    setCurrentStage(0);
    const interval = setInterval(() => {
      setCurrentStage((prev) => (prev < PROOF_STAGES.length - 1 ? prev + 1 : prev));
    }, 800);
    return () => clearInterval(interval);
  }, [loading]);

  // Reset collapsibles when switching tabs
  useEffect(() => {
    setProofOpen(false);
    setSignalsOpen(false);
    setError(null);
  }, [activeTab]);

  // Trigger on-chain verification after a successful local proof (age or name only)
  const triggerOnChainVerification = async (proofData, proofType) => {
    if (proofType !== 'age' && proofType !== 'name') return;
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

  const handleGenerateAge = async () => {
    setLoading(true);
    setError(null);
    setOnChainResults((prev) => ({ ...prev, age: null }));
    try {
      const res = await axios.post('/api/generate-proof', { userId });
      setResults((prev) => ({ ...prev, age: res.data }));
      if (onProofComplete) onProofComplete(res.data);
      // Auto-trigger on-chain verification
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
      // Auto-trigger on-chain verification
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
    try {
      const res = await axios.post('/api/generate-gender-proof', { userId, claimedGender });
      setResults((prev) => ({ ...prev, gender: res.data }));
    } catch (err) {
      setError(err.response?.data?.error || 'Server unreachable.');
    } finally {
      setLoading(false);
    }
  };

  // Loading state
  if (loading) {
    const tabLabel = TABS.find((t) => t.key === activeTab)?.label || 'Proof';
    return (
      <div className="card">
        <h2 className="card-title">Generating {tabLabel}</h2>
        <p className="card-description">
          Running the Groth16 zk-SNARK circuit. This may take a few seconds.
        </p>
        <div className="loading-container">
          <div className="spinner" />
          <div className="pipeline-status">
            {PROOF_STAGES.map((stage, index) => (
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

      {/* Tab selector */}
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

      {/* Tab content */}
      <div className="proof-tab-content" key={activeTab}>

        {/* ====== AGE TAB ====== */}
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

        {/* ====== NAME TAB ====== */}
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

        {/* ====== GENDER TAB ====== */}
        {activeTab === 'gender' && !currentResult && (
          <>
            <p className="card-description">
              Prove that the user's gender matches a claimed value without exposing it in the proof.
            </p>
            <div className="gender-selector">
              {GENDER_OPTIONS.map((opt) => (
                <button
                  key={opt.code}
                  className={`gender-option ${claimedGender === opt.code ? 'selected' : ''}`}
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

        {/* ====== ERROR (with no result) ====== */}
        {error && !currentResult && activeTab === 'age' && (
          <div className="proof-failed">
            <div className="proof-failed-icon">✕</div>
            <div className="proof-failed-title">Proof Failed</div>
            <div className="proof-failed-message">{error}</div>
          </div>
        )}

        {/* ====== RESULT DISPLAY ====== */}
        {currentResult && (
          <>
            {/* Timing */}
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

            {/* Privacy Note */}
            <div className="privacy-note">
              <span className="privacy-note-icon">🔒</span>
              <div className="privacy-note-text">
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

            {/* Panels */}
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

                {/* Age-specific public signals */}
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

                {/* Name-specific */}
                {activeTab === 'name' && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Claimed Name</div>
                    <div className="proof-attribute-value">{currentResult.claimedName || '—'}</div>
                  </div>
                )}

                {/* Gender-specific */}
                {activeTab === 'gender' && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Claimed Gender</div>
                    <div className="proof-attribute-value">{currentResult.claimedGenderLabel || '—'}</div>
                  </div>
                )}
              </div>

              <div className="proof-panel">
                <div className="proof-panel-title">What Is Hidden</div>
                {activeTab === 'age' && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Date of Birth</div>
                    <div className="redacted-block">████████████</div>
                  </div>
                )}
                {activeTab === 'name' && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Actual Name</div>
                    <div className="redacted-block">████████████</div>
                  </div>
                )}
                {activeTab === 'gender' && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Actual Gender Code</div>
                    <div className="redacted-block">████████████</div>
                  </div>
                )}
                <div className="proof-attribute">
                  <div className="proof-attribute-label">Aadhaar Number</div>
                  <div className="redacted-block">████████████</div>
                </div>
                <div className="hidden-note">
                  Private circuit inputs. Not present in proof or public signals.
                </div>
              </div>
            </div>

            {/* ====== ON-CHAIN VERIFICATION SECTION ====== */}
            {(activeTab === 'age' || activeTab === 'name') && currentResult.isValid && (
              <div className="onchain-section">
                <div className="onchain-header">
                  <span className="onchain-header-icon">⛓</span>
                  <span className="onchain-header-title">On-Chain Verification</span>
                </div>

                {currentOnChainLoading && (
                  <div className="onchain-body onchain-loading">
                    <div className="spinner spinner-small" />
                    <span className="onchain-loading-text">
                      Verifying proof on Polygon Amoy testnet...
                    </span>
                  </div>
                )}

                {!currentOnChainLoading && currentOnChain && currentOnChain.error === null && currentOnChain.onChainValid && (
                  <div className="onchain-body onchain-success">
                    <span className="onchain-badge-icon">✓</span>
                    <div className="onchain-badge-content">
                      <div className="onchain-badge-title">Verified on Polygon Amoy</div>
                      <a
                        className="onchain-contract-link"
                        href={`https://amoy.polygonscan.com/address/${currentOnChain.contractAddress}`}
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
                          href={`https://amoy.polygonscan.com/address/${currentOnChain.contractAddress}`}
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

            {/* Collapsible: Raw Proof */}
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

            {/* Collapsible: Public Signals */}
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

      {/* Start Over */}
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

import { useState, useEffect } from 'react';
import axios from 'axios';
import { checkOnChain } from '../contracts/onChainVerify';
import { hasPolicy, CHAIN } from '../contracts/contractConfig';
import { proveInBrowser } from '../prover/proveInBrowser';
import { buildMatchInput, normalizeName, signedFields, NAME_MAX } from '../prover/matchInput';
import { cutoffDate, formatDate, issuerOf } from '../verify/policy.js';
import ProofQR from './ProofQR';

// Every proof is made from the issuer-signed credential. Age uses
// CredentialAgeProof; name and gender use CredentialMatchProof.
const TABS = [
  { key: 'age', label: 'Age 18+' },
  { key: 'name', label: 'Name' },
  { key: 'gender', label: 'Gender' },
];
const CIRCUIT = { age: 'age', name: 'match', gender: 'match' };
const CONSTRAINTS = { age: '256,574', match: '260,903' };
const CHECKED = { age: 'the age check', name: 'the name match', gender: 'the gender match' };

const DESCRIPTIONS = {
  age: 'One circuit proves the issuer signed this credential and the date of birth inside it is 18 or older. Nothing else is revealed.',
  name: 'One circuit proves the issuer signed this credential and the name inside it matches the name you claim, ignoring case and spacing. Nothing else is revealed.',
  gender: 'One circuit proves the issuer signed this credential and the gender inside it matches the gender you claim. Nothing else is revealed.',
};

const serverStages = (kind) => [
  'Reading the document...',
  'Signing the credential (RSA-2048)...',
  `Proving signature + ${CHECKED[kind]} in one circuit...`,
];

const BROWSER_STAGES = [
  'Issuing the signed credential...',
  'Loading the proving key (cached after first use)...',
  'Proving in your browser...',
  'Verifying proof...',
];
const BROWSER_STAGE_INDEX = { loading: 1, proving: 2, verifying: 3 };

const PROVE_WHERE = [
  { key: 'server', label: 'Server' },
  { key: 'browser', label: 'Your browser' },
];

const UPLOADED = 'uploaded';

const SCENARIOS = [
  { key: 'valid', label: 'Valid adult' },
  { key: 'underage', label: 'Underage' },
  { key: 'year_only', label: 'Year of birth only' },
  { key: 'masked_id', label: 'Masked Aadhaar' },
  { key: 'ocr_fail', label: 'Unreadable' },
  { key: 'gender_missing', label: 'No gender' },
  { key: 'dob_garbled', label: 'Garbled DOB' },
  { key: 'invalid_date', label: 'DOB 31 Feb' },
  { key: 'malformed_name', label: 'Quote in name' },
  { key: 'long_name', label: 'Name too long' },
];

const GENDER_OPTIONS = [
  { code: 'M', label: 'Male' },
  { code: 'F', label: 'Female' },
  { code: 'O', label: 'Other' },
];
const GENDER_LABELS = { M: 'Male', F: 'Female', O: 'Other' };

const FAILURE_TITLES = {
  CREDENTIAL_UNPROCESSABLE: 'Retake the photo',
  AGE_REQUIREMENT_NOT_MET: 'Not eligible',
  CLAIM_MISMATCH: "Claim doesn't match",
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
  age: ['Date of Birth', 'Name', 'Gender', 'Aadhaar Number'],
  name: ['Date of Birth', 'Gender', 'Aadhaar Number'],
  gender: ['Name', 'Date of Birth', 'Aadhaar Number'],
};

const PRIVACY_NOTES = {
  age: 'Name, date of birth, Aadhaar number and gender were never exposed.',
  name: 'Only the claimed name was checked. Date of birth, gender and Aadhaar number were never exposed.',
  gender: 'Only the claimed gender was checked. Name, date of birth and Aadhaar number were never exposed.',
};

const ONCHAIN_RESULTS = {
  Accepted: 'Accepted by ZkIdPolicy',
  UntrustedIssuer: "Rejected: the issuer isn't on the policy's trusted list",
  CutoffTooLate: "Rejected: the cutoff date is later than today's 18-year cutoff",
  NothingClaimed: 'Rejected: the proof claims nothing',
  InvalidProof: "Rejected: the proof doesn't verify",
};

const UNDERAGE = 'This credential does not meet the minimum age requirement.';
const YEAR_ONLY_NOTE =
  'The card shows only a year of birth, so the check assumes the latest possible birthday in that year.';

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

// A failure decided in the browser, shaped like the server's.
function browserFailure(code, reason, error, stages) {
  const failure = {
    error,
    code,
    reason,
    retryable: false,
    stages: [...stages, { name: 'error', status: 'failed', detail: 'Checked in your browser' }],
  };
  return Object.assign(new Error(error), { failure });
}

function ProofStep({ userName, source, onStartOver }) {
  const [activeTab, setActiveTab] = useState('age');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState({ age: null, name: null, gender: null });
  const [failures, setFailures] = useState({ age: null, name: null, gender: null });
  const [policy, setPolicy] = useState({});
  const [currentStage, setCurrentStage] = useState(0);

  const [signedSource, setSignedSource] = useState(source?.file ? UPLOADED : source?.scenario || 'valid');
  const [proveWhere, setProveWhere] = useState('server');
  const [serverProving, setServerProving] = useState(true);
  const [browserStatus, setBrowserStatus] = useState('');

  const [claimedName, setClaimedName] = useState(userName || '');
  const [claimedGender, setClaimedGender] = useState('M');

  const [proofOpen, setProofOpen] = useState(false);
  const [signalsOpen, setSignalsOpen] = useState(false);

  const [onChain, setOnChain] = useState({});
  const [onChainLoading, setOnChainLoading] = useState({});

  const setFor = (setter, kind, value) => setter((prev) => ({ ...prev, [kind]: value }));

  // Hosts without the proving keys (e.g. Vercel) only support browser proving.
  useEffect(() => {
    axios
      .get('/api/health')
      .then(({ data }) => {
        if (data.serverProving === false) {
          setServerProving(false);
          setProveWhere('browser');
        }
      })
      .catch(() => {});
  }, []);

  const inBrowser = proveWhere === 'browser';
  const loadingStages = inBrowser ? BROWSER_STAGES : serverStages(activeTab);

  // Server proofs animate on a timer; browser proofs report real progress.
  useEffect(() => {
    if (!loading) return;
    setCurrentStage(0);
    if (inBrowser) return;
    const interval = setInterval(() => {
      setCurrentStage((prev) => (prev < loadingStages.length - 1 ? prev + 1 : prev));
    }, 800);
    return () => clearInterval(interval);
  }, [loading]);

  useEffect(() => {
    setProofOpen(false);
    setSignalsOpen(false);
  }, [activeTab]);

  const claimsFor = (kind) =>
    kind === 'name' ? { name: claimedName.trim() } : kind === 'gender' ? { gender: claimedGender } : {};

  const postCredentialSource = (url, fields = {}) => {
    if (signedSource === UPLOADED) {
      const formData = new FormData();
      formData.append('image', source.file);
      for (const [key, value] of Object.entries(fields)) formData.append(key, value);
      return axios.post(url, formData);
    }
    return axios.post(url, { scenario: signedSource, ...fields });
  };

  const proveOnServer = async (kind) => {
    if (kind === 'age') return (await postCredentialSource('/api/signed-proof')).data;
    const claims = claimsFor(kind);
    const fields = kind === 'name' ? { claimedName: claims.name } : { claimedGender: claims.gender };
    return (await postCredentialSource('/api/signed-match-proof', fields)).data;
  };

  // The server only issues the credential; proving happens on this device.
  // Claims are checked first, so a wrong one gets a clear answer instead of a failed proof.
  const proveOnDevice = async (kind) => {
    const { data } = await postCredentialSource('/api/issue-credential');
    const { input, stages, card } = data;
    const claims = claimsFor(kind);

    let circuitInput = input;
    if (kind === 'age') {
      // A year-only YYYY-99-99 compares after every date in that year, as in the circuit.
      const at = input.dobIndex + 7;
      const dob = String.fromCharCode(...input.msg.slice(at, at + 10));
      if (Number(dob.replaceAll('-', '')) > input.thresholdDate) {
        const error = card?.yearOfBirthOnly ? `${UNDERAGE} ${YEAR_ONLY_NOTE}` : UNDERAGE;
        throw browserFailure('AGE_REQUIREMENT_NOT_MET', 'underage', error, stages);
      }
    } else {
      const signed = signedFields(input.msg);
      if (kind === 'name' && normalizeName(claims.name) !== signed.name.toLowerCase()) {
        throw browserFailure('CLAIM_MISMATCH', 'name_mismatch', "The name on this credential doesn't match the claimed name.", stages);
      }
      if (kind === 'gender' && claims.gender !== signed.gender) {
        throw browserFailure('CLAIM_MISMATCH', 'gender_mismatch', "The gender on this credential doesn't match the claimed gender.", stages);
      }
      circuitInput = buildMatchInput(input, claims);
    }

    const result = await proveInBrowser(circuitInput, {
      circuit: CIRCUIT[kind],
      onStage: (stage) => {
        setCurrentStage(BROWSER_STAGE_INDEX[stage]);
        if (stage !== 'loading') setBrowserStatus('');
      },
      onProgress: (name, pct) => setBrowserStatus(`Downloading ${name}: ${pct}%`),
    });
    return {
      ...result,
      card,
      message: `${kind === 'age' ? 'AGE_OVER_18' : `${kind.toUpperCase()}_MATCH`}: VERIFIED (proved in your browser)`,
      claimedName: claims.name ?? null,
      claimedGender: claims.gender ?? null,
      claimedGenderLabel: claims.gender ? GENDER_LABELS[claims.gender] : null,
      stages: [...stages, { name: 'proof_complete', status: 'complete', detail: `Proved in your browser in ${result.proofDuration}ms` }],
    };
  };

  // The checks ZkIdPolicy makes, applied here so the result shows what a relying party would accept.
  const applyPolicy = async (kind, result) => {
    const issuer = await issuerOf(result.publicSignals);
    if (kind !== 'age') return setFor(setPolicy, kind, { issuer });
    const threshold = Number(result.publicSignals[17]);
    const cutoff = cutoffDate();
    setFor(setPolicy, kind, { issuer, ageOk: threshold <= cutoff, bornOnOrBefore: formatDate(threshold), cutoff: formatDate(cutoff) });
  };

  const runOnChain = async (kind, result) => {
    if (!hasPolicy() || !result.isValid) return;
    setFor(setOnChainLoading, kind, true);
    try {
      setFor(setOnChain, kind, await checkOnChain(result.proof, result.publicSignals, kind));
    } finally {
      setFor(setOnChainLoading, kind, false);
    }
  };

  const generate = async () => {
    const kind = activeTab;
    setLoading(true);
    setBrowserStatus('');
    setFor(setFailures, kind, null);
    setFor(setOnChain, kind, null);
    setFor(setPolicy, kind, null);
    try {
      const result = inBrowser ? await proveOnDevice(kind) : await proveOnServer(kind);
      setFor(setResults, kind, result);
      applyPolicy(kind, result);
      runOnChain(kind, result);
    } catch (err) {
      setFor(setFailures, kind, err.failure || err.response?.data || { error: err.message || 'Server unreachable.' });
    } finally {
      setLoading(false);
      setBrowserStatus('');
    }
  };

  const startAgain = (kind) => {
    setFor(setResults, kind, null);
    setFor(setOnChain, kind, null);
    setFor(setPolicy, kind, null);
  };

  const tabLabel = TABS.find((t) => t.key === activeTab)?.label || 'Proof';

  if (loading) {
    return (
      <div className="card">
        <h2 className="card-title">Generating {tabLabel} Proof</h2>
        <p className="card-description">
          {inBrowser
            ? 'Your device is generating the proof. The server never sees the private inputs.'
            : `Verifying the issuer signature and ${CHECKED[activeTab]} in one ${CONSTRAINTS[CIRCUIT[activeTab]]}-constraint circuit. This takes about 4 seconds.`}
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
          {browserStatus && <div className="browser-status">{browserStatus}</div>}
        </div>
      </div>
    );
  }

  const currentResult = results[activeTab];
  const currentFailure = failures[activeTab];
  const currentPolicy = policy[activeTab] || null;
  const currentOnChain = onChain[activeTab] || null;
  const currentOnChainLoading = onChainLoading[activeTab] || false;
  const nameMissing = activeTab === 'name' && !claimedName.trim();

  return (
    <div className="card">
      <h2 className="card-title">Zero-Knowledge Proofs</h2>
      <p className="card-description">
        Every proof is made from the issuer-signed credential, so it can only attest to what the issuer signed.
        A relying party also checks that the issuer is one it trusts.
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
        {!currentResult && (
          <>
            <p className="card-description">{DESCRIPTIONS[activeTab]}</p>

            {activeTab === 'name' && (
              <div className="name-input-group">
                <label className="name-input-label">Name to prove</label>
                <input
                  type="text"
                  className="name-input"
                  value={claimedName}
                  maxLength={NAME_MAX}
                  onChange={(e) => setClaimedName(e.target.value)}
                  placeholder="Enter the name on the card..."
                />
              </div>
            )}

            {activeTab === 'gender' && (
              <>
                <label className="name-input-label">Gender to prove</label>
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
              </>
            )}

            <label className="name-input-label">Credential source</label>
            <div className="option-grid">
              {[...(source?.file ? [{ key: UPLOADED, label: 'Uploaded image' }] : []), ...SCENARIOS].map((opt) => (
                <button
                  key={opt.key}
                  className={`option-button ${signedSource === opt.key ? 'selected' : ''}`}
                  onClick={() => setSignedSource(opt.key)}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            {serverProving && (
              <>
                <label className="name-input-label">Where to prove</label>
                <div className="option-group">
                  {PROVE_WHERE.map((opt) => (
                    <button
                      key={opt.key}
                      className={`option-button ${proveWhere === opt.key ? 'selected' : ''}`}
                      onClick={() => setProveWhere(opt.key)}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </>
            )}
            {inBrowser && (
              <p className="card-description">
                The server only issues and signs the credential. Your browser generates the proof, so no server
                sees the private inputs. Each circuit's 135 MB proving key downloads once and is cached.
              </p>
            )}
            <div className="step-actions">
              <button className="btn btn-primary btn-full" onClick={generate} disabled={nameMissing}>
                Generate {tabLabel} Proof
              </button>
            </div>
            {currentFailure && (
              <>
                <div className="proof-failed">
                  <div className="proof-failed-icon">{currentFailure.retryable ? '↻' : '✕'}</div>
                  <div className="proof-failed-title">{FAILURE_TITLES[currentFailure.code] || 'Proof Failed'}</div>
                  <div className="proof-failed-message">{currentFailure.error}</div>
                  {currentFailure.code && (
                    <div className="proof-failed-code">
                      {currentFailure.code} · {currentFailure.reason} · {currentFailure.retryable ? 'retryable' : 'not retryable'}
                    </div>
                  )}
                </div>
                {currentFailure.stages && <StageTrace stages={currentFailure.stages} />}
              </>
            )}
          </>
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
                <strong>{PRIVACY_NOTES[activeTab]}</strong> The proof shows the issuer signed this credential.
              </div>
            </div>

            {(currentResult.card?.yearOfBirthOnly || currentResult.card?.maskedId) && (
              <div className="privacy-note">
                <span className="privacy-note-icon">ⓘ</span>
                <div className="privacy-note-text">
                  {currentResult.card.yearOfBirthOnly && activeTab === 'age' && <div>{YEAR_ONLY_NOTE}</div>}
                  {currentResult.card.yearOfBirthOnly && activeTab !== 'age' && <div>The card shows only a year of birth.</div>}
                  {currentResult.card.maskedId && (
                    <div>Masked Aadhaar: the issuer signed only the last 4 digits of the Aadhaar number.</div>
                  )}
                </div>
              </div>
            )}

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
                <div className="proof-attribute">
                  <div className="proof-attribute-label">Issuer (checked against trusted list)</div>
                  <div className="proof-attribute-value">
                    {!currentPolicy
                      ? '—'
                      : currentPolicy.issuer.name
                      ? `✓ ${currentPolicy.issuer.name} (key ${currentPolicy.issuer.keyId})`
                      : `✕ Untrusted key ${currentPolicy.issuer.keyId}`}
                  </div>
                </div>

                {activeTab === 'age' && currentPolicy && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Born on or before (public signal)</div>
                    <div className="proof-attribute-value">
                      {currentPolicy.bornOnOrBefore} {currentPolicy.ageOk ? '✓ 18+ today' : `✕ later than today's cutoff ${currentPolicy.cutoff}`}
                    </div>
                  </div>
                )}

                {activeTab === 'name' && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Claimed name (hash is a public signal)</div>
                    <div className="proof-attribute-value">{currentResult.claimedName || '—'}</div>
                  </div>
                )}

                {activeTab === 'gender' && (
                  <div className="proof-attribute">
                    <div className="proof-attribute-label">Claimed gender (public signal)</div>
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
                <div className="hidden-note">
                  Private circuit inputs. Not present in proof or public signals.
                </div>
              </div>
            </div>

            {hasPolicy() && currentResult.isValid && (
              <div className="onchain-section">
                <div className="onchain-header">
                  <span className="onchain-header-icon">⛓</span>
                  <span className="onchain-header-title">On-Chain Policy Check</span>
                </div>

                {(currentOnChainLoading || !currentOnChain) && (
                  <div className="onchain-body onchain-loading">
                    <div className="spinner spinner-small" />
                    <span className="onchain-loading-text">Asking ZkIdPolicy on {CHAIN.name}...</span>
                  </div>
                )}

                {!currentOnChainLoading && currentOnChain && currentOnChain.error === null && (
                  <div className={`onchain-body ${currentOnChain.result === 'Accepted' ? 'onchain-success' : 'onchain-fail'}`}>
                    <span className="onchain-badge-icon">{currentOnChain.result === 'Accepted' ? '✓' : '✕'}</span>
                    <div className="onchain-badge-content">
                      <div className="onchain-badge-title">
                        {ONCHAIN_RESULTS[currentOnChain.result] || currentOnChain.result} on {CHAIN.name}
                      </div>
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

                {!currentOnChainLoading && currentOnChain && currentOnChain.error !== null && (
                  <div className="onchain-body onchain-error">
                    <span className="onchain-badge-icon">⚠</span>
                    <div className="onchain-badge-content">
                      <div className="onchain-badge-title">On-chain check failed</div>
                      <div className="onchain-error-detail">{currentOnChain.error}</div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'age' && currentResult.isValid && (
              <ProofQR proof={currentResult.proof} publicSignals={currentResult.publicSignals} />
            )}
            <StageTrace stages={currentResult.stages} />
            <div className="step-actions">
              <button className="btn btn-outline btn-full" onClick={() => startAgain(activeTab)}>
                Try another credential
              </button>
            </div>

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

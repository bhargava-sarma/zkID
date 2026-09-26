import { useState } from 'react';
import UploadStep from './components/UploadStep';
import PreprocessStep from './components/PreprocessStep';
import StorageStep from './components/StorageStep';
import ProofStep from './components/ProofStep';

const STEPS = [
  { number: 1, label: 'Upload' },
  { number: 2, label: 'Preprocess' },
  { number: 3, label: 'Store' },
  { number: 4, label: 'Prove' },
];

function App() {
  const [currentStep, setCurrentStep] = useState(1);
  const [uploadData, setUploadData] = useState(null);
  const [source, setSource] = useState(null);

  // source: { file } or { scenario }, reused by the signed-credential proof.
  const handleUploadComplete = (data, uploadSource) => {
    setUploadData(data);
    setSource(uploadSource);
    setCurrentStep(2);
  };

  const handleNextStep = () => {
    setCurrentStep((prev) => Math.min(prev + 1, 4));
  };

  const handleStartOver = () => {
    setCurrentStep(1);
    setUploadData(null);
    setSource(null);
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>zkID</h1>
        <p>Zero-Knowledge Proof Framework for Cross-Institutional KYC Compliance</p>
      </header>

      <nav className="stepper">
        {STEPS.map((step, index) => (
          <div key={step.number} style={{ display: 'flex', alignItems: 'center' }}>
            <div
              className={`step-indicator ${
                currentStep === step.number
                  ? 'active'
                  : currentStep > step.number
                  ? 'completed'
                  : ''
              }`}
            >
              <div className="step-number">
                {currentStep > step.number ? '✓' : step.number}
              </div>
              <span className="step-label">{step.label}</span>
            </div>
            {index < STEPS.length - 1 && (
              <div
                className={`step-connector ${
                  currentStep > step.number ? 'completed' : ''
                }`}
              />
            )}
          </div>
        ))}
      </nav>

      <main>
        {currentStep === 1 && (
          <UploadStep onComplete={handleUploadComplete} />
        )}
        {currentStep === 2 && (
          <PreprocessStep data={uploadData} onNext={handleNextStep} />
        )}
        {currentStep === 3 && (
          <StorageStep data={uploadData} onNext={handleNextStep} />
        )}
        {currentStep === 4 && (
          <ProofStep
            userId={uploadData?.userId}
            userName={uploadData?.stored?.name}
            source={source}
            onStartOver={handleStartOver}
          />
        )}
      </main>

      <footer className="footer">
        Raw identity data never stored or transmitted &middot; ZK proofs via Groth16 &middot; Blockchain-ready
      </footer>
    </div>
  );
}

export default App;

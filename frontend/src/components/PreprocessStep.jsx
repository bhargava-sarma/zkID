function PreprocessStep({ data, onNext }) {
  if (!data) return null;

  const transformations = data.transformations || [];

  return (
    <div className="card">
      <h2 className="card-title">Data Preprocessing</h2>
      <p className="card-description">
        Raw document data is reduced to hashes and encoded values before the
        KYC record is stored. Proofs don't use these values: they are made from
        the issuer-signed credential.
      </p>

      <div className="pipeline-complete-badge">
        <span className="badge-icon">✓</span>
        <span>All {transformations.length} transformations completed successfully</span>
      </div>

      <div className="pipeline">
        {transformations.map((step, index) => (
          <div key={index}>
            <div className="pipeline-step">
              <div className="pipeline-step-label">{step.label}</div>
              <div className="pipeline-step-value">{step.value}</div>
              <div className="pipeline-step-explanation">{step.explanation}</div>
            </div>
            {index < transformations.length - 1 && (
              <div className="pipeline-arrow">↓</div>
            )}
          </div>
        ))}
      </div>

      <div className="step-actions">
        <button className="btn btn-primary" onClick={onNext}>
          Continue
        </button>
      </div>
    </div>
  );
}

export default PreprocessStep;

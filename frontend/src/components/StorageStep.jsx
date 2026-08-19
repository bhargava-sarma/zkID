function StorageStep({ data, onNext }) {
  if (!data) return null;
  const stored = data.stored || {};
  const genderLabels = { 0: 'Unknown', 1: 'Male', 2: 'Female', 3: 'Other' };

  return (
    <div className="card">
      <h2 className="card-title">Secure Storage</h2>
      <p className="card-description">
        Only privacy-safe values are stored in the database. Raw personal data is
        immediately discarded after preprocessing.
      </p>

      <div className="supabase-badge">✓ Supabase — Insert confirmed</div>

      <div className="storage-section">
        <div className="storage-section-title">✓ Stored in Database</div>
        <div className="storage-row">
          <span className="storage-key">id</span>
          <span className="storage-value">{stored.id}</span>
        </div>
        <div className="storage-row">
          <span className="storage-key">name</span>
          <span className="storage-value">{stored.name}</span>
        </div>
        <div className="storage-row">
          <span className="storage-key">dob_encoded</span>
          <span className="storage-value">
            {stored.dob_encoded === '[protected]' ? <span className="redacted">[protected]</span> : stored.dob_encoded}
          </span>
        </div>
        <div className="storage-row">
          <span className="storage-key">aadhaar_hash</span>
          <span className="storage-value">
            {stored.aadhaar_hash ? stored.aadhaar_hash.substring(0, 24) + '...' : ''}
          </span>
        </div>
        <div className="storage-row">
          <span className="storage-key">name_hash</span>
          <span className="storage-value">
            {stored.name_hash ? stored.name_hash.substring(0, 24) + '...' : '—'}
          </span>
        </div>
        <div className="storage-row">
          <span className="storage-key">gender_code</span>
          <span className="storage-value">
            {stored.gender_code === '[protected]'
              ? <span className="redacted">[protected]</span>
              : stored.gender_code !== null && stored.gender_code !== undefined
              ? `${stored.gender_code} (${genderLabels[stored.gender_code] || 'Unknown'})`
              : '—'}
          </span>
        </div>
        <div className="storage-row">
          <span className="storage-key">created_at</span>
          <span className="storage-value">
            {stored.created_at ? new Date(stored.created_at).toLocaleString() : ''}
          </span>
        </div>
      </div>

      <div className="storage-section">
        <div className="storage-section-title">✕ Not Stored (Redacted)</div>
        <div className="storage-row">
          <span className="storage-key">raw_dob</span>
          <span className="storage-value redacted">██ REDACTED ██</span>
        </div>
        <div className="storage-row">
          <span className="storage-key">raw_aadhaar</span>
          <span className="storage-value redacted">██ REDACTED ██</span>
        </div>
      </div>

      <div className="step-actions">
        <button className="btn btn-primary" onClick={onNext}>Continue</button>
      </div>
    </div>
  );
}

export default StorageStep;

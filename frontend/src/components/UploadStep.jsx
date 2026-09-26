import { useState, useRef } from 'react';
import axios from 'axios';

const ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/jpg'];
const MAX_BYTES = 4 * 1024 * 1024; // Vercel caps request bodies at 4.5 MB

function fileError(file) {
  if (!ALLOWED_TYPES.includes(file.type)) return `Unsupported file type: ${file.type}. Only PNG, JPG, and JPEG are allowed.`;
  if (file.size > MAX_BYTES) return 'File too large. Maximum size is 4 MB.';
  return null;
}

const PIPELINE_STAGES = [
  { key: 'upload_received', label: 'Upload received' },
  { key: 'ocr_started', label: 'OCR running' },
  { key: 'ocr_complete', label: 'OCR complete' },
  { key: 'preprocessing_complete', label: 'Preprocessing complete' },
  { key: 'supabase_stored', label: 'Data stored in Supabase' },
];

function UploadStep({ onComplete }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [activeStages, setActiveStages] = useState([]);
  const [demoLoading, setDemoLoading] = useState(null);
  const inputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0];
      const problem = fileError(droppedFile);
      if (problem) {
        setError(problem);
        return;
      }
      setFile(droppedFile);
      setError(null);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      const problem = fileError(selectedFile);
      if (problem) {
        setError(problem);
        e.target.value = '';
        return;
      }
      setFile(selectedFile);
      setError(null);
    }
  };

  const animateStages = (stages) => {
    setActiveStages([]);
    stages.forEach((stage, index) => {
      setTimeout(() => {
        setActiveStages((prev) => [...prev, stage]);
      }, index * 400);
    });
  };

  const handleUpload = async () => {
    if (!file) return;

    setLoading(true);
    setError(null);
    setActiveStages([]);

    const preStages = [
      { name: 'upload_received', status: 'complete', detail: `${file.name}` },
      { name: 'ocr_started', status: 'running', detail: 'Tesseract OCR processing...' },
    ];
    animateStages(preStages);

    try {
      const formData = new FormData();
      formData.append('aadhaar', file);

      const response = await axios.post('/api/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });

      if (response.data.stages) {
        animateStages(response.data.stages);
        await new Promise((resolve) => setTimeout(resolve, response.data.stages.length * 400 + 500));
      }

      onComplete(response.data, { file });
    } catch (err) {
      const message =
        err.response?.data?.error ||
        'Server unreachable. Ensure backend is running.';
      setError(message);

      if (err.response?.data?.stages) {
        animateStages(err.response.data.stages);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDemo = async (scenario) => {
    setDemoLoading(scenario);
    setError(null);
    setActiveStages([]);

    animateStages([
      { name: 'upload_received', status: 'running', detail: `Demo: ${scenario}...` },
    ]);

    try {
      const response = await axios.post('/api/demo', { scenario });

      if (response.data.stages) {
        animateStages(response.data.stages);
        await new Promise((resolve) => setTimeout(resolve, response.data.stages.length * 400 + 500));
      }

      onComplete(response.data, { scenario });
    } catch (err) {
      const message =
        err.response?.data?.error ||
        'Demo scenario failed.';
      setError(message);

      if (err.response?.data?.stages) {
        animateStages(err.response.data.stages);
      }
    } finally {
      setDemoLoading(null);
    }
  };

  if (loading || demoLoading) {
    return (
      <div className="card">
        <h2 className="card-title">
          {demoLoading ? `Running Demo: ${demoLoading}` : 'Processing Aadhaar'}
        </h2>
        <p className="card-description">
          Running the pipeline — each stage is tracked below.
        </p>

        <div className="loading-container">
          <div className="spinner" />
          <div className="pipeline-status">
            {activeStages.map((stage, index) => (
              <div
                key={index}
                className={`pipeline-status-item status-${stage.status}`}
                style={{ animationDelay: `${index * 0.1}s` }}
              >
                <span className="status-icon">
                  {stage.status === 'complete' ? '✓' : stage.status === 'failed' ? '✕' : '●'}
                </span>
                <span className="status-label">
                  {PIPELINE_STAGES.find((s) => s.key === stage.name)?.label || stage.name}
                </span>
                {stage.detail && (
                  <span className="status-detail">{stage.detail}</span>
                )}
              </div>
            ))}
          </div>
        </div>

        {error && <div className="error-message">{error}</div>}
      </div>
    );
  }

  return (
    <div className="card">
      <h2 className="card-title">Upload Aadhaar Card</h2>
      <p className="card-description">
        Upload an image of an Aadhaar card. The image is processed in memory only
        and never saved to disk.
      </p>

      <div
        className={`upload-zone ${file ? 'has-file' : ''} ${dragActive ? 'has-file' : ''}`}
        onClick={() => inputRef.current?.click()}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <div className="upload-icon">↑</div>
        <div className="upload-text">
          {file ? 'File selected' : 'Click or drag to upload'}
        </div>
        <div className="upload-subtext">PNG, JPG, or JPEG only (max 4 MB)</div>
        {file && <div className="file-name">{file.name}</div>}
        <input
          ref={inputRef}
          type="file"
          className="upload-input"
          accept="image/png,image/jpeg,image/jpg"
          onChange={handleFileChange}
        />
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="step-actions">
        <button
          className="btn btn-primary btn-full"
          onClick={handleUpload}
          disabled={!file}
        >
          Extract &amp; Process
        </button>
      </div>

      <div className="demo-section">
        <div className="or-divider">or try a demo scenario</div>
        <div className="demo-cards">
          <div
            className="demo-card demo-valid"
            onClick={() => handleDemo('valid')}
          >
            <div className="demo-card-icon">✓</div>
            <div className="demo-card-label">Valid Aadhaar</div>
            <div className="demo-card-desc">Adult, DOB 1990. Full pipeline succeeds.</div>
          </div>
          <div
            className="demo-card demo-ocr"
            onClick={() => handleDemo('ocr_fail')}
          >
            <div className="demo-card-icon">⚠</div>
            <div className="demo-card-label">Poor Image</div>
            <div className="demo-card-desc">OCR extraction fails on unreadable input.</div>
          </div>
          <div
            className="demo-card demo-underage"
            onClick={() => handleDemo('underage')}
          >
            <div className="demo-card-icon">✕</div>
            <div className="demo-card-label">Underage</div>
            <div className="demo-card-desc">Born 2015. Proof generation will fail.</div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default UploadStep;

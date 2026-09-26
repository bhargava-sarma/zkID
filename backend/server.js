const express = require('express');
const cors = require('cors');
const multer = require('multer');
require('dotenv').config({ path: '../.env' });

const { extractAadhaarData } = require('./ocr');
const { preprocessData, computeNameHash } = require('./preprocessing');
const { storeUser, getUserById } = require('./db');
const { generateProof, generateNameProof, generateGenderProof } = require('./proofgen');
const { buildCanonicalPayload, signCredential, CredentialError } = require('./signedcredential');
const { generateComposedProof } = require('./composedproof');

const app = express();
const PORT = process.env.PORT || 3001;

const ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/jpg'];

// Memory storage only: images never touch disk.
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (ALLOWED_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${file.mimetype}. Only PNG, JPG, and JPEG are allowed.`));
    }
  },
  limits: { fileSize: 10 * 1024 * 1024 },
});

app.use(cors());
app.use(express.json());

const OCR_FAIL_MESSAGE =
  'Could not extract required fields: DOB, Aadhaar number. Please use a clear, well-lit image.';
const PREPROCESS_DETAIL = 'DOB → YYYYMMDD, Name → hash, Gender → code';

const DEMO_OCR = {
  valid: { name: 'Rajesh Kumar', dob: '01/01/1990', aadhaarNumber: '1234 5678 9012', gender: 'Male' },
  underage: { name: 'Priya Sharma', dob: '15/06/2015', aadhaarNumber: '1098 7654 3210', gender: 'Female' },
};

// Failure modes for /api/signed-proof. null = OCR itself fails.
const SIGNED_DEMO_OCR = {
  ...DEMO_OCR,
  ocr_fail: null,
  malformed_name: { ...DEMO_OCR.valid, name: 'Ra"jesh Kumar' },
  gender_missing: { ...DEMO_OCR.valid, gender: null },
  dob_garbled: { ...DEMO_OCR.valid, dob: 'O1/O1/199O' },
  long_name: { ...DEMO_OCR.valid, name: 'A'.repeat(60) },
};

const stage = (name, status, detail) => ({ name, status, detail, timestamp: new Date().toISOString() });

// Private values are redacted before reaching the client.
function storedResponse(processed, user, stages) {
  return {
    success: true,
    userId: user.id,
    transformations: processed.transformations.map(({ label, explanation }) => ({
      label,
      value: '[protected]',
      explanation,
    })),
    stages,
    stored: {
      id: user.id,
      name: user.name,
      dob_encoded: '[protected]',
      aadhaar_hash: user.aadhaar_hash ? user.aadhaar_hash.substring(0, 8) + '...' : null,
      name_hash: user.name_hash ? user.name_hash.substring(0, 8) + '...' : null,
      gender_code: user.gender_code != null ? '[protected]' : null,
      created_at: user.created_at,
    },
  };
}

function storeProcessed(processed) {
  return storeUser(
    processed.name,
    processed.dobEncoded,
    processed.aadhaarHash,
    processed.nameHash,
    processed.genderCode
  );
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/upload', upload.single('aadhaar'), async (req, res) => {
  const stages = [];
  const pushStage = (...args) => stages.push(stage(...args));

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file uploaded.' });
    }

    const sizeKb = (req.file.size / 1024).toFixed(1);
    pushStage('upload_received', 'complete', `File: ${req.file.originalname} (${sizeKb}KB)`);
    console.log(`[UPLOAD] Received file: ${req.file.originalname} (${req.file.mimetype}, ${sizeKb}KB)`);

    pushStage('ocr_started', 'running', 'Tesseract OCR processing...');
    const ocr = await extractAadhaarData(req.file.buffer);
    pushStage('ocr_complete', 'complete', `Extracted: Name, DOB, Aadhaar${ocr.gender ? ', Gender' : ''}`);

    const processed = preprocessData(ocr.name, ocr.dob, ocr.aadhaarNumber, ocr.gender);
    pushStage('preprocessing_complete', 'complete', PREPROCESS_DETAIL);

    const user = await storeProcessed(processed);
    pushStage('supabase_stored', 'complete', `User ID: ${user.id}`);

    res.json(storedResponse(processed, user, stages));
  } catch (err) {
    console.error('[UPLOAD] Error:', err.message);
    pushStage('error', 'failed', err.message);
    const statusCode = err.message.includes('Could not extract')
      ? 422
      : err.message.includes('Unsupported file type')
      ? 415
      : err.message.includes('Database error')
      ? 502
      : 500;
    res.status(statusCode).json({
      error: err.message || 'Server error during upload processing.',
      stages,
    });
  }
});

app.post('/api/generate-proof', async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId is required.' });

    const user = await getUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const result = await generateProof(user.dob_encoded);

    res.json({
      proof: result.proof,
      publicSignals: result.publicSignals,
      isValid: result.isValid,
      message: result.message,
      thresholdDate: result.thresholdDate,
      todayDate: result.todayDate,
      minimumAgeYears: result.minimumAgeYears,
      proofDuration: result.proofDuration,
      verificationDuration: result.verificationDuration,
    });
  } catch (err) {
    console.error('[PROOF:AGE] Error:', err.message);
    const statusCode = err.message.includes('Age condition') ? 400 : 500;
    res.status(statusCode).json({ error: err.message || 'Proof generation failed.' });
  }
});

app.post('/api/generate-name-proof', async (req, res) => {
  try {
    const { userId, claimedName } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId is required.' });
    if (!claimedName) return res.status(400).json({ error: 'claimedName is required.' });

    const user = await getUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    if (!user.name_hash) {
      return res.status(400).json({ error: 'User does not have a name hash stored. Re-upload with the latest version.' });
    }

    const claimedNameHash = computeNameHash(claimedName);
    const result = await generateNameProof(user.name_hash, claimedNameHash);

    res.json({
      proof: result.proof,
      publicSignals: result.publicSignals,
      isValid: result.isValid,
      message: result.message,
      claimedName,
      claimedNameHash,
      proofDuration: result.proofDuration,
      verificationDuration: result.verificationDuration,
    });
  } catch (err) {
    console.error('[PROOF:NAME] Error:', err.message);
    const statusCode = err.message.includes('does not match') ? 400 : 500;
    res.status(statusCode).json({ error: err.message || 'Name proof generation failed.' });
  }
});

app.post('/api/generate-gender-proof', async (req, res) => {
  try {
    const { userId, claimedGender } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId is required.' });
    if (!claimedGender) return res.status(400).json({ error: 'claimedGender is required (1=Male, 2=Female, 3=Other).' });

    const user = await getUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    if (user.gender_code == null) {
      return res.status(400).json({ error: 'User does not have a gender code stored. Gender may not have been detected during OCR.' });
    }

    const result = await generateGenderProof(user.gender_code, parseInt(claimedGender));

    res.json({
      proof: result.proof,
      publicSignals: result.publicSignals,
      isValid: result.isValid,
      message: result.message,
      claimedGender: parseInt(claimedGender),
      claimedGenderLabel: result.claimedGenderLabel,
      proofDuration: result.proofDuration,
      verificationDuration: result.verificationDuration,
    });
  } catch (err) {
    console.error('[PROOF:GENDER] Error:', err.message);
    const statusCode = err.message.includes('does not match') ? 400 : 500;
    res.status(statusCode).json({ error: err.message || 'Gender proof generation failed.' });
  }
});

app.post('/api/demo', async (req, res) => {
  const { scenario } = req.body;
  console.log(`[DEMO] Running scenario: ${scenario}`);

  if (scenario === 'ocr_fail') {
    return res.status(422).json({
      error: OCR_FAIL_MESSAGE,
      stages: [
        stage('upload_received', 'complete', 'Demo: poor quality image'),
        stage('ocr_started', 'running', 'Tesseract OCR processing...'),
        stage('error', 'failed', OCR_FAIL_MESSAGE),
      ],
    });
  }
  if (!Object.hasOwn(DEMO_OCR, scenario)) {
    return res.status(400).json({ error: 'Invalid scenario. Use: valid, ocr_fail, or underage.' });
  }

  try {
    const ocr = DEMO_OCR[scenario];
    const processed = preprocessData(ocr.name, ocr.dob, ocr.aadhaarNumber, ocr.gender);
    const user = await storeProcessed(processed);
    res.json(
      storedResponse(processed, user, [
        stage('upload_received', 'complete', `Demo: ${scenario} Aadhaar`),
        stage('ocr_complete', 'complete', 'Extracted: Name, DOB, Aadhaar, Gender'),
        stage('preprocessing_complete', 'complete', PREPROCESS_DETAIL),
        stage('supabase_stored', 'complete', `User ID: ${user.id}`),
      ])
    );
  } catch (err) {
    console.error(`[DEMO] ${scenario} scenario error:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// Issuer-signed path. No DB write, and no fallback to the legacy endpoints:
// if a credential can't be signed or proven, the request fails.
app.post('/api/signed-proof', upload.single('image'), async (req, res) => {
  const stages = [];
  const pushStage = (...args) => stages.push(stage(...args));
  const scenario = req.body && req.body.scenario;

  try {
    let ocr;
    if (req.file) {
      pushStage('upload_received', 'complete', `${req.file.mimetype}, ${req.file.size} bytes`);
      pushStage('ocr_started', 'running', 'Tesseract OCR processing...');
      ocr = await extractAadhaarData(req.file.buffer);
      pushStage('ocr_complete', 'complete', 'Extracted: Name, DOB, ID, Gender');
    } else if (scenario) {
      if (!Object.hasOwn(SIGNED_DEMO_OCR, scenario)) {
        return res.status(400).json({
          error: `Unknown scenario. Use one of: ${Object.keys(SIGNED_DEMO_OCR).join(', ')}.`,
        });
      }
      pushStage('upload_received', 'complete', `Demo scenario: ${scenario}`);
      if (SIGNED_DEMO_OCR[scenario] === null) {
        pushStage('ocr_started', 'running', 'Tesseract OCR processing...');
        throw new Error(OCR_FAIL_MESSAGE);
      }
      ocr = SIGNED_DEMO_OCR[scenario];
      pushStage('ocr_complete', 'complete', 'Extracted (simulated)');
    } else {
      return res.status(400).json({ error: 'Provide an image file or a demo scenario.' });
    }

    pushStage('credential_signing', 'running', 'Constructing canonical payload...');
    const payload = buildCanonicalPayload(ocr);
    const { credential, circuitInputs, canonicalBytes } = signCredential(payload);
    pushStage(
      'credential_signed',
      'complete',
      `${canonicalBytes} canonical + ${circuitInputs.padding.pad_byte_count} pad = 119 bytes, RSA-2048`
    );

    pushStage('proof_started', 'running', 'RSA verify + in-circuit extraction + age check...');
    const result = await generateComposedProof(circuitInputs, payload.dob);
    pushStage('proof_complete', 'complete', `Proved in ${result.proofDuration}ms`);

    res.json({
      success: true,
      guarantee: 'issuer-signed',
      proof: result.proof,
      publicSignals: result.publicSignals,
      isValid: result.isValid,
      message: result.message,
      thresholdDate: result.thresholdDate,
      credentialSha256: credential.sha256,
      proofDuration: result.proofDuration,
      verificationDuration: result.verificationDuration,
      stages,
    });
  } catch (err) {
    if (err instanceof CredentialError) {
      // detail can quote field contents: log only, never send.
      console.error(`[SIGNED-PROOF] ${err.code}/${err.reason}: ${err.detail}`);
      pushStage('error', 'failed', err.userMessage);
      return res.status(err.status).json({
        error: err.userMessage,
        code: err.code,
        reason: err.reason,
        retryable: err.retryable,
        stages,
      });
    }
    console.error(`[SIGNED-PROOF] unhandled: ${err.message}`);
    pushStage('error', 'failed', err.message);
    return res.status(422).json({
      error: err.message,
      code: 'CREDENTIAL_UNPROCESSABLE',
      reason: 'ocr_extraction_failed',
      retryable: true,
      stages,
    });
  }
});

// Multer errors (file type, size).
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'File too large. Maximum size is 10MB.' });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err.message && err.message.includes('Unsupported file type')) {
    return res.status(415).json({ error: err.message });
  }
  next(err);
});

app.listen(PORT, () => {
  console.log(`ZK-KYC backend running on http://localhost:${PORT}`);
});

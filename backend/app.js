const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { extractAadhaarData } = require('./ocr');
const { YEAR_ONLY_DOB, MASKED_AADHAAR } = require('./aadhaartext');
const { preprocessData } = require('./preprocessing');
const { storeUser } = require('./db');
const { buildCanonicalPayload, cardNotes, signCredential, CredentialError } = require('./signedcredential');
const { generateComposedProof, proverInput, serverProvingAvailable } = require('./composedproof');
const { generateMatchProof, matchProvingAvailable, parseClaims, ClaimError } = require('./matchproof');

const app = express();

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
  // Vercel caps request bodies at 4.5 MB.
  limits: { fileSize: 4 * 1024 * 1024 },
});

app.use(cors());
app.use(express.json());

const OCR_FAIL_MESSAGE =
  'Could not extract required fields: DOB, Aadhaar number. Please use a clear, well-lit image.';
const PREPROCESS_DETAIL = 'DOB → YYYYMMDD, Name → hash, Gender → code';

const DEMO_OCR = {
  valid: { name: 'Rajesh Kumar', dob: '01/01/1990', aadhaarNumber: '1234 5678 9012', gender: 'Male' },
  underage: { name: 'Priya Sharma', dob: '15/06/2015', aadhaarNumber: '1098 7654 3210', gender: 'Female' },
  // The card prints only a year of birth.
  year_only: { name: 'Sunita Devi', dob: '1985', aadhaarNumber: '2345 6789 0123', gender: 'Female' },
  // Masked Aadhaar: only the last 4 digits are printed.
  masked_id: { name: 'Arjun Mehta', dob: '12/03/1992', aadhaarNumber: 'XXXX XXXX 4321', gender: 'Male' },
};

// Failure modes for /api/signed-proof. null = OCR itself fails.
const SIGNED_DEMO_OCR = {
  ...DEMO_OCR,
  ocr_fail: null,
  malformed_name: { ...DEMO_OCR.valid, name: 'Ra"jesh Kumar' },
  gender_missing: { ...DEMO_OCR.valid, gender: null },
  dob_garbled: { ...DEMO_OCR.valid, dob: 'O1/O1/199O' },
  invalid_date: { ...DEMO_OCR.valid, dob: '31/02/1990' },
  long_name: { ...DEMO_OCR.valid, name: 'A'.repeat(60) },
};

const stage = (name, status, detail) => ({ name, status, detail, timestamp: new Date().toISOString() });

// "Name, DOB, Aadhaar, Gender", naming the year-only and masked variants.
function extractedFields(ocr) {
  return [
    'Name',
    YEAR_ONLY_DOB.test(ocr.dob) ? 'Year of birth' : 'DOB',
    MASKED_AADHAAR.test(ocr.aadhaarNumber) ? 'Masked Aadhaar' : 'Aadhaar',
    ...(ocr.gender ? ['Gender'] : []),
  ].join(', ');
}

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
  res.json({
    status: 'ok',
    serverProving: serverProvingAvailable() && matchProvingAvailable(),
    timestamp: new Date().toISOString(),
  });
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
    pushStage('ocr_complete', 'complete', `Extracted: ${extractedFields(ocr)}`);

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
    return res.status(400).json({ error: `Invalid scenario. Use one of: ${[...Object.keys(DEMO_OCR), 'ocr_fail'].join(', ')}.` });
  }

  try {
    const ocr = DEMO_OCR[scenario];
    const processed = preprocessData(ocr.name, ocr.dob, ocr.aadhaarNumber, ocr.gender);
    const user = await storeProcessed(processed);
    res.json(
      storedResponse(processed, user, [
        stage('upload_received', 'complete', `Demo: ${scenario} Aadhaar`),
        stage('ocr_complete', 'complete', `Extracted: ${extractedFields(ocr)}`),
        stage('preprocessing_complete', 'complete', PREPROCESS_DETAIL),
        stage('supabase_stored', 'complete', `User ID: ${user.id}`),
      ])
    );
  } catch (err) {
    console.error(`[DEMO] ${scenario} scenario error:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

class BadRequest extends Error {}

// OCR (or a canned scenario) -> signed credential. No DB write on either signed path.
async function issueSignedCredential(req, pushStage) {
  const scenario = req.body && req.body.scenario;
  let ocr;
  if (req.file) {
    pushStage('upload_received', 'complete', `${req.file.mimetype}, ${req.file.size} bytes`);
    pushStage('ocr_started', 'running', 'Tesseract OCR processing...');
    ocr = await extractAadhaarData(req.file.buffer);
    pushStage('ocr_complete', 'complete', `Extracted: ${extractedFields(ocr)}`);
  } else if (scenario) {
    if (!Object.hasOwn(SIGNED_DEMO_OCR, scenario)) {
      throw new BadRequest(`Unknown scenario. Use one of: ${Object.keys(SIGNED_DEMO_OCR).join(', ')}.`);
    }
    pushStage('upload_received', 'complete', `Demo scenario: ${scenario}`);
    if (SIGNED_DEMO_OCR[scenario] === null) {
      pushStage('ocr_started', 'running', 'Tesseract OCR processing...');
      throw new Error(OCR_FAIL_MESSAGE);
    }
    ocr = SIGNED_DEMO_OCR[scenario];
    pushStage('ocr_complete', 'complete', 'Extracted (simulated)');
  } else {
    throw new BadRequest('Provide an image file or a demo scenario.');
  }

  pushStage('credential_signing', 'running', 'Constructing canonical payload...');
  const payload = buildCanonicalPayload(ocr);
  const signed = signCredential(payload);
  pushStage(
    'credential_signed',
    'complete',
    `${signed.canonicalBytes} canonical + ${signed.circuitInputs.padding.pad_byte_count} pad = 119 bytes, RSA-2048`
  );
  return { payload, card: cardNotes(payload), ...signed };
}

function sendSignedError(res, err, stages) {
  if (err instanceof BadRequest || err instanceof ClaimError) {
    return res.status(400).json({ error: err.message });
  }
  if (err instanceof CredentialError) {
    // detail can quote field contents: log only, never send.
    console.error(`[SIGNED] ${err.code}/${err.reason}: ${err.detail}`);
    stages.push(stage('error', 'failed', err.userMessage));
    return res.status(err.status).json({
      error: err.userMessage,
      code: err.code,
      reason: err.reason,
      retryable: err.retryable,
      stages,
    });
  }
  console.error(`[SIGNED] unhandled: ${err.message}`);
  stages.push(stage('error', 'failed', err.message));
  return res.status(422).json({
    error: err.message,
    code: 'CREDENTIAL_UNPROCESSABLE',
    reason: 'ocr_extraction_failed',
    retryable: true,
    stages,
  });
}

// Issue, sign and prove on the server. No fallback to the legacy endpoints.
app.post('/api/signed-proof', upload.single('image'), async (req, res) => {
  const stages = [];
  const pushStage = (...args) => stages.push(stage(...args));

  try {
    const { payload, card, credential, circuitInputs } = await issueSignedCredential(req, pushStage);

    pushStage('proof_started', 'running', 'RSA verify + in-circuit extraction + age check...');
    const result = await generateComposedProof(circuitInputs, payload.dob);
    pushStage('proof_complete', 'complete', `Proved in ${result.proofDuration}ms`);

    res.json({
      success: true,
      guarantee: 'issuer-signed',
      card,
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
    sendSignedError(res, err, stages);
  }
});

// Issue, sign and prove a name and/or gender claim on the server:
// { claimedName?, claimedGender? (M, F or O) } plus an image or a scenario.
app.post('/api/signed-match-proof', upload.single('image'), async (req, res) => {
  const stages = [];
  const pushStage = (...args) => stages.push(stage(...args));

  try {
    const claims = parseClaims(req.body);
    const { card, circuitInputs } = await issueSignedCredential(req, pushStage);

    pushStage('proof_started', 'running', 'RSA verify + in-circuit name/gender match...');
    const result = await generateMatchProof(circuitInputs, claims);
    pushStage('proof_complete', 'complete', `Proved in ${result.proofDuration}ms`);

    res.json({ success: true, guarantee: 'issuer-signed', card, ...result, stages });
  } catch (err) {
    sendSignedError(res, err, stages);
  }
});

// Issue and sign only: the holder proves in their own browser. The response
// carries the holder's own credential (including the raw ID) as circuit input;
// it is not stored or logged.
app.post('/api/issue-credential', upload.single('image'), async (req, res) => {
  const stages = [];
  const pushStage = (...args) => stages.push(stage(...args));

  try {
    const { card, credential, circuitInputs } = await issueSignedCredential(req, pushStage);
    res.json({ success: true, input: proverInput(circuitInputs), card, credentialSha256: credential.sha256, stages });
  } catch (err) {
    sendSignedError(res, err, stages);
  }
});

// Multer errors (file type, size).
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'File too large. Maximum size is 4MB.' });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err.message && err.message.includes('Unsupported file type')) {
    return res.status(415).json({ error: err.message });
  }
  next(err);
});

module.exports = app;

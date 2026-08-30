const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
require('dotenv').config({ path: '../.env' });

const { extractAadhaarData } = require('./ocr');
const { preprocessData, computeNameHash } = require('./preprocessing');
const { storeUser, getUserById } = require('./db');
const { generateProof, generateNameProof, generateGenderProof } = require('./proofgen');
const { buildCanonicalPayload, signCredential, CredentialError } = require('./signedcredential');
const { generateComposedProof } = require('./composedproof');

const app = express();
const PORT = process.env.PORT || 3001;

// Allowed image MIME types
const ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/jpg'];

// Multer — memory storage only, image never written to disk
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (ALLOWED_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${file.mimetype}. Only PNG, JPG, and JPEG are allowed.`));
    }
  },
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
});

app.use(cors());
app.use(express.json());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Step 1-3: Upload, Extract, Preprocess, Store
app.post('/api/upload', upload.single('aadhaar'), async (req, res) => {
  const stages = [];
  const pushStage = (name, status, detail) => {
    stages.push({ name, status, detail, timestamp: new Date().toISOString() });
  };

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file uploaded.' });
    }

    pushStage('upload_received', 'complete', `File: ${req.file.originalname} (${(req.file.size / 1024).toFixed(1)}KB)`);
    console.log(`[UPLOAD] Received file: ${req.file.originalname} (${req.file.mimetype}, ${(req.file.size / 1024).toFixed(1)}KB)`);

    // Step 1: OCR extraction from image buffer (never saved to disk)
    pushStage('ocr_started', 'running', 'Tesseract OCR processing...');
    const ocrResult = await extractAadhaarData(req.file.buffer);
    pushStage('ocr_complete', 'complete', `Extracted: Name, DOB, Aadhaar${ocrResult.gender ? ', Gender' : ''}`);

    // Step 2: Preprocess — convert DOB to days, hash Aadhaar, hash name, encode gender
    const processed = preprocessData(
      ocrResult.name,
      ocrResult.dob,
      ocrResult.aadhaarNumber,
      ocrResult.gender
    );
    pushStage('preprocessing_complete', 'complete', 'DOB → days, Name → hash, Gender → code');

    // Step 3: Store in Supabase
    const storedUser = await storeUser(
      processed.name,
      processed.dobEncoded,
      processed.aadhaarHash,
      processed.nameHash,
      processed.genderCode
    );
    pushStage('supabase_stored', 'complete', `User ID: ${storedUser.id}`);

    // Sanitize transformations — redact actual sensitive values for client display
    const sanitizedTransformations = processed.transformations.map((t) => ({
      label: t.label,
      value: '[protected]',
      explanation: t.explanation,
    }));

    res.json({
      success: true,
      userId: storedUser.id,
      transformations: sanitizedTransformations,
      stages,
      stored: {
        id: storedUser.id,
        name: storedUser.name,
        dob_encoded: '[protected]',
        aadhaar_hash: storedUser.aadhaar_hash ? storedUser.aadhaar_hash.substring(0, 8) + '...' : null,
        name_hash: storedUser.name_hash ? storedUser.name_hash.substring(0, 8) + '...' : null,
        gender_code: storedUser.gender_code !== null && storedUser.gender_code !== undefined ? '[protected]' : null,
        created_at: storedUser.created_at,
      },
    });
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

// Step 4a: Generate Age ZK Proof
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

// Step 4b: Generate Name ZK Proof
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

    // Compute the hash of the claimed name to use as the public input
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

// Step 4c: Generate Gender ZK Proof
app.post('/api/generate-gender-proof', async (req, res) => {
  try {
    const { userId, claimedGender } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId is required.' });
    if (!claimedGender) return res.status(400).json({ error: 'claimedGender is required (1=Male, 2=Female, 3=Other).' });

    const user = await getUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    if (user.gender_code === null || user.gender_code === undefined) {
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

// Demo endpoint — returns hardcoded data for demo scenarios
app.post('/api/demo', async (req, res) => {
  const { scenario } = req.body;
  console.log(`[DEMO] Running scenario: ${scenario}`);

  if (scenario === 'valid') {
    const processed = preprocessData('Rajesh Kumar', '01/01/1990', '1234 5678 9012', 'Male');

    try {
      const storedUser = await storeUser(
        processed.name, processed.dobEncoded, processed.aadhaarHash,
        processed.nameHash, processed.genderCode
      );

      const stages = [
        { name: 'upload_received', status: 'complete', detail: 'Demo: valid Aadhaar image', timestamp: new Date().toISOString() },
        { name: 'ocr_complete', status: 'complete', detail: 'Extracted: Name, DOB, Aadhaar, Gender', timestamp: new Date().toISOString() },
        { name: 'preprocessing_complete', status: 'complete', detail: 'DOB → days, Name → hash, Gender → code', timestamp: new Date().toISOString() },
        { name: 'supabase_stored', status: 'complete', detail: `User ID: ${storedUser.id}`, timestamp: new Date().toISOString() },
      ];

      const sanitizedTransformations = processed.transformations.map((t) => ({
        label: t.label,
        value: '[protected]',
        explanation: t.explanation,
      }));

      res.json({
        success: true,
        userId: storedUser.id,
        transformations: sanitizedTransformations,
        stages,
        stored: {
          id: storedUser.id,
          name: storedUser.name,
          dob_encoded: '[protected]',
          aadhaar_hash: storedUser.aadhaar_hash ? storedUser.aadhaar_hash.substring(0, 8) + '...' : null,
          name_hash: storedUser.name_hash ? storedUser.name_hash.substring(0, 8) + '...' : null,
          gender_code: storedUser.gender_code !== null && storedUser.gender_code !== undefined ? '[protected]' : null,
          created_at: storedUser.created_at,
        },
      });
    } catch (err) {
      console.error('[DEMO] valid scenario error:', err.message);
      res.status(500).json({ error: err.message });
    }
  } else if (scenario === 'ocr_fail') {
    const stages = [
      { name: 'upload_received', status: 'complete', detail: 'Demo: poor quality image', timestamp: new Date().toISOString() },
      { name: 'ocr_started', status: 'running', detail: 'Tesseract OCR processing...', timestamp: new Date().toISOString() },
      { name: 'error', status: 'failed', detail: 'Could not extract required fields: DOB, Aadhaar number. Please use a clear, well-lit image.', timestamp: new Date().toISOString() },
    ];
    res.status(422).json({
      error: 'Could not extract required fields: DOB, Aadhaar number. Please use a clear, well-lit image.',
      stages,
    });
  } else if (scenario === 'underage') {
    const processed = preprocessData('Priya Sharma', '15/06/2015', '9876 5432 1098', 'Female');

    try {
      const storedUser = await storeUser(
        processed.name, processed.dobEncoded, processed.aadhaarHash,
        processed.nameHash, processed.genderCode
      );

      const stages = [
        { name: 'upload_received', status: 'complete', detail: 'Demo: underage Aadhaar', timestamp: new Date().toISOString() },
        { name: 'ocr_complete', status: 'complete', detail: 'Extracted: Name, DOB, Aadhaar, Gender', timestamp: new Date().toISOString() },
        { name: 'preprocessing_complete', status: 'complete', detail: 'DOB → days, Name → hash, Gender → code', timestamp: new Date().toISOString() },
        { name: 'supabase_stored', status: 'complete', detail: `User ID: ${storedUser.id}`, timestamp: new Date().toISOString() },
      ];

      const sanitizedTransformations = processed.transformations.map((t) => ({
        label: t.label,
        value: '[protected]',
        explanation: t.explanation,
      }));

      res.json({
        success: true,
        userId: storedUser.id,
        transformations: sanitizedTransformations,
        stages,
        stored: {
          id: storedUser.id,
          name: storedUser.name,
          dob_encoded: '[protected]',
          aadhaar_hash: storedUser.aadhaar_hash ? storedUser.aadhaar_hash.substring(0, 8) + '...' : null,
          name_hash: storedUser.name_hash ? storedUser.name_hash.substring(0, 8) + '...' : null,
          gender_code: storedUser.gender_code !== null && storedUser.gender_code !== undefined ? '[protected]' : null,
          created_at: storedUser.created_at,
        },
      });
    } catch (err) {
      console.error('[DEMO] underage scenario error:', err.message);
      res.status(500).json({ error: err.message });
    }
  } else {
    res.status(400).json({ error: 'Invalid scenario. Use: valid, ocr_fail, or underage.' });
  }
});

// =============================================================================
// Signed-credential proof  (additive; the legacy endpoints are untouched)
// =============================================================================
//
// This is the only endpoint whose proof attests to what an ISSUER signed.
// /api/upload and /api/generate-proof prove facts about values THIS SERVER
// computed, which is a strictly weaker guarantee -- see README section 7.
//
// There is deliberately no fallback from this path to the legacy one. If a
// credential cannot be built or proven, it fails; it never silently downgrades
// to an unsigned proof while implying the same assurance.
//
// The raw 12-digit id is required to build the canonical payload. It lives only
// in memory here, goes into the signed bytes (a PRIVATE circuit input), and is
// never logged, never written to disk, and never sent to Supabase -- this
// endpoint performs no database write at all.

// Canned OCR outputs, so the failure modes can be exercised without hunting for
// a photo that happens to break in the right way.
const SIGNED_DEMO_SCENARIOS = {
  valid: { name: 'Rajesh Kumar', dob: '01/01/1990', aadhaarNumber: '1234 5678 9012', gender: 'Male' },
  underage: { name: 'Priya Sharma', dob: '15/06/2015', aadhaarNumber: '9876 5432 1098', gender: 'Female' },
  // OCR itself fails before any credential can be built.
  ocr_fail: '__OCR_THROWS__',
  // A name carrying a character the ASCII guard rejects.
  malformed_name: { name: 'Ra"jesh Kumar', dob: '01/01/1990', aadhaarNumber: '1234 5678 9012', gender: 'Male' },
  // Gender undetected -- a hard failure, never defaulted.
  gender_missing: { name: 'Rajesh Kumar', dob: '01/01/1990', aadhaarNumber: '1234 5678 9012', gender: null },
  // OCR misread: letter O for zero.
  dob_garbled: { name: 'Rajesh Kumar', dob: 'O1/O1/199O', aadhaarNumber: '1234 5678 9012', gender: 'Male' },
  // Canonical form over 119 bytes.
  long_name: { name: 'A'.repeat(60), dob: '01/01/1990', aadhaarNumber: '1234 5678 9012', gender: 'Male' },
};

app.post('/api/signed-proof', upload.single('image'), async (req, res) => {
  const stages = [];
  const pushStage = (name, status, detail) =>
    stages.push({ name, status, detail, timestamp: new Date().toISOString() });

  const scenario = req.body && req.body.scenario;

  try {
    // ---- Stage 1: obtain OCR fields -------------------------------------
    let ocrResult;
    if (req.file) {
      pushStage('upload_received', 'complete', `${req.file.mimetype}, ${req.file.size} bytes`);
      pushStage('ocr_started', 'running', 'Tesseract OCR processing...');
      ocrResult = await extractAadhaarData(req.file.buffer);
      pushStage('ocr_complete', 'complete', 'Extracted: Name, DOB, ID, Gender');
    } else if (scenario) {
      const canned = SIGNED_DEMO_SCENARIOS[scenario];
      if (!canned) {
        return res.status(400).json({
          error: `Unknown scenario. Use one of: ${Object.keys(SIGNED_DEMO_SCENARIOS).join(', ')}.`,
        });
      }
      pushStage('upload_received', 'complete', `Demo scenario: ${scenario}`);
      if (canned === '__OCR_THROWS__') {
        pushStage('ocr_started', 'running', 'Tesseract OCR processing...');
        throw new Error(
          'Could not extract required fields: DOB, Aadhaar number. Please use a clear, well-lit image.'
        );
      }
      ocrResult = canned;
      pushStage('ocr_complete', 'complete', 'Extracted (simulated)');
    } else {
      return res.status(400).json({ error: 'Provide an image file or a demo scenario.' });
    }

    // ---- Stage 2: build + sign the credential ---------------------------
    pushStage('credential_signing', 'running', 'Constructing canonical payload...');
    const payload = buildCanonicalPayload(ocrResult);
    const { credential, circuitInputs, canonicalBytes } = signCredential(payload);
    pushStage(
      'credential_signed',
      'complete',
      `${canonicalBytes} canonical + ${circuitInputs.padding.pad_byte_count} pad = 119 bytes, RSA-2048`
    );

    // ---- Stage 3: composed proof ----------------------------------------
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
      // detail can quote field contents, so it goes to the log, not the client.
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
    // OCR's own extraction failure, or anything unanticipated.
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

// Handle multer errors (file type, size)
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

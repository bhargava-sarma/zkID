const os = require('os');
const Tesseract = require('tesseract.js');

// Tesseract loads its wasm engine by path at runtime, which bundlers can't trace.
// Resolving the files here keeps them in serverless (Vercel) bundles.
require.resolve('tesseract.js-core/tesseract-core.wasm');
require.resolve('tesseract.js-core/tesseract-core-simd.wasm');
require.resolve('tesseract.js-core/tesseract-core-lstm.wasm');
require.resolve('tesseract.js-core/tesseract-core-simd-lstm.wasm');
const { parseAadhaarText, YEAR_ONLY_DOB, MASKED_AADHAAR } = require('./aadhaartext');

// English plus Hindi: with English alone, Hindi lines come out as Latin noise
// that can pass for a name. OCR_LANGS adds other scripts, e.g. eng+hin+tam.
const OCR_LANGS = process.env.OCR_LANGS || 'eng+hin';

async function extractAadhaarData(imageBuffer) {
  console.log(`[OCR] Starting Tesseract recognition (${OCR_LANGS})...`);
  const startTime = Date.now();

  const {
    data: { text },
  } = await Tesseract.recognize(imageBuffer, OCR_LANGS, { cachePath: os.tmpdir() }); // writable on serverless hosts

  console.log(`[OCR] Recognition complete in ${Date.now() - startTime}ms`);
  console.log(`[OCR] Raw text preview: "${text.substring(0, 50).replace(/\n/g, ' ')}..."`);

  const result = parseAadhaarText(text);
  console.log(`[OCR] Gender detected: ${result.gender || 'not found'}`);

  const missing = [];
  if (!result.name) missing.push('Name');
  if (!result.dob) missing.push('DOB');
  if (!result.aadhaarNumber) missing.push('Aadhaar number');

  if (missing.length > 0) {
    console.log(`[OCR] Extraction failed — missing: ${missing.join(', ')}`);
    throw new Error(
      `Could not extract required fields: ${missing.join(', ')}. Please use a clear, well-lit image.`
    );
  }

  const dobShown = YEAR_ONLY_DOB.test(result.dob) ? '**** (year only)' : '**/**/****';
  const idShown = `****-****-${result.aadhaarNumber.slice(-4)}${MASKED_AADHAAR.test(result.aadhaarNumber) ? ' (masked)' : ''}`;
  console.log(`[OCR] Extracted — Name: ${result.name}, DOB: ${dobShown}, Gender: ${result.gender || 'N/A'}, Aadhaar: ${idShown}`);

  return result;
}

module.exports = { extractAadhaarData };

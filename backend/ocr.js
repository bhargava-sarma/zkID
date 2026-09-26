const os = require('os');
const Tesseract = require('tesseract.js');
const { isCalendarDate } = require('../mock-issuer/sign_credential');

async function extractAadhaarData(imageBuffer) {
  console.log('[OCR] Starting Tesseract recognition...');
  const startTime = Date.now();

  const {
    data: { text },
  } = await Tesseract.recognize(imageBuffer, 'eng', { cachePath: os.tmpdir() }); // writable on serverless hosts

  console.log(`[OCR] Recognition complete in ${Date.now() - startTime}ms`);
  console.log(`[OCR] Raw text preview: "${text.substring(0, 50).replace(/\n/g, ' ')}..."`);

  const result = {
    rawText: text,
    name: null,
    dob: null,
    aadhaarNumber: null,
    gender: null,
  };

  // Prefer a labelled "DOB: DD/MM/YYYY", else the first DD/MM/YYYY anywhere.
  const dobMatch =
    text.match(/DOB\s*[:\-]\s*(\d{2}\/\d{2}\/\d{4})/i) || text.match(/(\d{2}\/\d{2}\/\d{4})/);
  if (dobMatch) result.dob = dobMatch[1];

  const aadhaarMatch = text.match(/(\d{4}\s\d{4}\s\d{4})/);
  if (aadhaarMatch) result.aadhaarNumber = aadhaarMatch[1];

  const genderMatch = text.match(/\b(Male|Female|Transgender|Other)\b/i);
  if (genderMatch) {
    const raw = genderMatch[1].toLowerCase();
    result.gender = raw === 'male' ? 'Male' : raw === 'female' ? 'Female' : 'Other';
  }
  console.log(`[OCR] Gender detected: ${result.gender || 'not found'}`);

  // Name is the line immediately above the DOB line.
  if (result.dob) {
    const lines = text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    const dobLine = lines.findIndex((l) => l.includes(result.dob) || /DOB/i.test(l));
    if (dobLine > 0) {
      const nameCandidate = lines[dobLine - 1].replace(/[^a-zA-Z\s]/g, '').trim();
      if (nameCandidate.length > 1) result.name = nameCandidate;
    }

    // A misread like 31/02 is dropped, never passed on as a real DOB.
    const [day, month, year] = result.dob.split('/').map(Number);
    if (!isCalendarDate(year, month, day)) {
      console.log('[OCR] DOB is not a real calendar date; treating as unreadable');
      result.dob = null;
    }
  }

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

  console.log(`[OCR] Extracted — Name: ${result.name}, DOB: **/**/****, Gender: ${result.gender || 'N/A'}, Aadhaar: ****-****-${result.aadhaarNumber.slice(-4)}`);

  return result;
}

module.exports = { extractAadhaarData };

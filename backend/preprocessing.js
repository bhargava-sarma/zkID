const crypto = require('crypto');
const { YEAR_ONLY_DOB, MASKED_AADHAAR } = require('./aadhaartext');

// Shown in the UI. Values are redacted server-side, so only labels are listed.
const DOB_STEPS = [
  {
    label: 'Raw DOB from OCR',
    explanation: 'Date of birth as extracted from the Aadhaar card via OCR',
  },
  {
    label: 'Normalized ISO Date',
    explanation: 'Converted to ISO 8601 format for standardized processing',
  },
  {
    label: 'Encoded Date (YYYYMMDD)',
    explanation:
      'Date encoded as year*10000 + month*100 + day, so integer comparison is chronological comparison.',
  },
];

const YEAR_ONLY_STEPS = [
  {
    label: 'Year of Birth from OCR',
    explanation: 'This card prints only a year of birth, not a full date.',
  },
  {
    label: 'Encoded Date (YYYY9999)',
    explanation:
      'Encoded as year*10000 + 9999, which sorts after every real date in that year, so it can never overstate age.',
  },
];

const AADHAAR_STEP = {
  label: 'Aadhaar SHA-256 Hash',
  explanation: 'One-way cryptographic hash. Only the hash is stored; the original number is discarded.',
};

const MASKED_STEP = {
  label: 'Masked Aadhaar',
  explanation: 'Only the last 4 digits are printed, so no Aadhaar hash is computed or stored.',
};

const OTHER_STEPS = [
  {
    label: 'Name Hash',
    explanation:
      'SHA-256 hash of the normalized name, converted to a BigInt.',
  },
  {
    label: 'Gender Code',
    explanation:
      'Gender encoded as integer (1=Male, 2=Female, 3=Other).',
  },
];

// First 31 bytes of SHA-256, so the value fits the BN128 field.
function computeNameHash(name) {
  const hash = crypto.createHash('sha256').update(name.toLowerCase().trim()).digest('hex');
  return BigInt('0x' + hash.substring(0, 62)).toString();
}

// Male=1, Female=2, Other=3, missing=0.
function genderToCode(gender) {
  if (!gender) return 0;
  const g = gender.toLowerCase();
  if (g === 'male') return 1;
  if (g === 'female') return 2;
  return 3;
}

function preprocessData(name, dobString, aadhaarNumber, gender) {
  console.log('[PREPROCESS] Starting data transformation...');

  // DD/MM/YYYY -> year*10000 + month*100 + day: integer order is date order.
  // A year-only DOB becomes year*10000 + 9999, after every real date that year.
  const yearOnly = YEAR_ONLY_DOB.test(dobString);
  let dobEncoded;
  if (yearOnly) {
    dobEncoded = Number(dobString) * 10000 + 9999;
  } else {
    const [day, month, year] = dobString.split('/');
    dobEncoded = Number(year) * 10000 + Number(month) * 100 + Number(day);
  }
  console.log(`[PREPROCESS] DOB encoded: ${dobEncoded}${yearOnly ? ' (year only)' : ''}`);

  // The raw Aadhaar number is not returned: it is discarded here. A masked
  // number keeps only 4 digits, so there is nothing worth hashing.
  const masked = MASKED_AADHAAR.test(aadhaarNumber);
  const aadhaarHash = masked
    ? null
    : crypto.createHash('sha256').update(aadhaarNumber.replace(/\s/g, '')).digest('hex');
  console.log(`[PREPROCESS] Aadhaar ${masked ? 'masked: no hash stored' : `hashed: ${aadhaarHash.substring(0, 12)}...`}`);

  const nameHash = computeNameHash(name);
  console.log(`[PREPROCESS] Name hashed: ${nameHash.substring(0, 16)}...`);

  const genderCode = genderToCode(gender);
  console.log(`[PREPROCESS] Gender: ${gender || 'Unknown'} → code ${genderCode}`);

  return {
    name,
    dobEncoded,
    aadhaarHash,
    nameHash,
    genderCode,
    transformations: [...(yearOnly ? YEAR_ONLY_STEPS : DOB_STEPS), masked ? MASKED_STEP : AADHAAR_STEP, ...OTHER_STEPS],
  };
}

module.exports = { preprocessData, computeNameHash };

const crypto = require('crypto');

// Shown in the UI. Values are redacted server-side, so only labels are listed.
const TRANSFORMATIONS = [
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
      'Date encoded as year*10000 + month*100 + day, so integer comparison is chronological comparison. This is the private input to the Age ZK circuit.',
  },
  {
    label: 'Aadhaar SHA-256 Hash',
    explanation: 'One-way cryptographic hash. Only the hash is stored; the original number is discarded.',
  },
  {
    label: 'Name Hash (Circuit Input)',
    explanation:
      'SHA-256 hash of the normalized name, converted to a BigInt. This is the private input to the Name ZK circuit.',
  },
  {
    label: 'Gender Code',
    explanation:
      'Gender encoded as integer (1=Male, 2=Female, 3=Other). This is the private input to the Gender ZK circuit.',
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
  const [day, month, year] = dobString.split('/');
  const dobEncoded = Number(year) * 10000 + Number(month) * 100 + Number(day);
  console.log(`[PREPROCESS] DOB encoded: ${dobEncoded}`);

  // The raw Aadhaar number is not returned: it is discarded here.
  const aadhaarHash = crypto.createHash('sha256').update(aadhaarNumber.replace(/\s/g, '')).digest('hex');
  console.log(`[PREPROCESS] Aadhaar hashed: ${aadhaarHash.substring(0, 12)}...`);

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
    transformations: TRANSFORMATIONS,
  };
}

module.exports = { preprocessData, computeNameHash };

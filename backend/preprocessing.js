const crypto = require('crypto');

/**
 * Convert a name string into a BigInt suitable for circuit input.
 * Uses SHA-256 and takes the first 31 bytes to fit within BN128 field.
 */
function computeNameHash(name) {
  const normalized = name.toLowerCase().trim();
  const hash = crypto.createHash('sha256').update(normalized).digest('hex');
  // Take first 31 bytes (62 hex chars) to stay within BN128 field prime
  const truncated = hash.substring(0, 62);
  return BigInt('0x' + truncated).toString();
}

/**
 * Convert gender string to integer code for circuit input.
 * Male=1, Female=2, Other=3, null=0
 */
function genderToCode(gender) {
  if (!gender) return 0;
  const g = gender.toLowerCase();
  if (g === 'male') return 1;
  if (g === 'female') return 2;
  return 3; // Other / Transgender
}

function preprocessData(name, dobString, aadhaarNumber, gender) {
  console.log('[PREPROCESS] Starting data transformation...');

  // Step 1: Normalize DOB from DD/MM/YYYY to ISO YYYY-MM-DD
  const [day, month, year] = dobString.split('/');
  const isoDate = `${year}-${month}-${day}`;
  console.log(`[PREPROCESS] DOB normalized — year: ${year}`);

  // Step 2: Encode DOB as a single comparable integer: year*10000 + month*100 + day.
  // Integer ordering on this encoding is chronological ordering on the date, so
  // the age circuit needs one comparison and no date arithmetic. This replaced
  // days-since-epoch, whose 18*365 threshold ignored leap days.
  const dobEncoded = Number(year) * 10000 + Number(month) * 100 + Number(day);
  console.log(`[PREPROCESS] DOB encoded: ${dobEncoded}`);

  // Step 3: Hash Aadhaar number with SHA-256
  const aadhaarClean = aadhaarNumber.replace(/\s/g, '');
  const aadhaarHash = crypto.createHash('sha256').update(aadhaarClean).digest('hex');
  console.log(`[PREPROCESS] Aadhaar hashed: ${aadhaarHash.substring(0, 12)}...`);

  // Step 4: Compute name hash (BigInt string for circuit input)
  const nameHash = computeNameHash(name);
  console.log(`[PREPROCESS] Name hashed: ${nameHash.substring(0, 16)}...`);

  // Step 5: Convert gender to code
  const genderCode = genderToCode(gender);
  const genderLabel = gender || 'Unknown';
  console.log(`[PREPROCESS] Gender: ${genderLabel} → code ${genderCode}`);

  console.log('[PREPROCESS] Transformation complete');

  // Return both display data and processed values
  // Raw Aadhaar is NOT included in return — it's discarded here
  return {
    name,
    rawDob: dobString,
    isoDate,
    dobEncoded,
    aadhaarHash,
    nameHash,
    gender: genderLabel,
    genderCode,
    // Transformation steps for frontend display
    transformations: [
      {
        label: 'Raw DOB from OCR',
        value: dobString,
        explanation: 'Date of birth as extracted from the Aadhaar card via OCR',
      },
      {
        label: 'Normalized ISO Date',
        value: isoDate,
        explanation: 'Converted to ISO 8601 format for standardized processing',
      },
      {
        label: 'Encoded Date (YYYYMMDD)',
        value: `${dobEncoded}`,
        explanation:
          'Date encoded as year*10000 + month*100 + day, so integer comparison is chronological comparison. This is the private input to the Age ZK circuit.',
      },
      {
        label: 'Aadhaar SHA-256 Hash',
        value: aadhaarHash.substring(0, 20) + '...',
        explanation:
          'One-way cryptographic hash. Original Aadhaar number is irreversibly discarded after this step.',
      },
      {
        label: 'Name Hash (Circuit Input)',
        value: nameHash.substring(0, 24) + '...',
        explanation:
          'SHA-256 hash of the normalized name, converted to a BigInt. This is the private input to the Name ZK circuit.',
      },
      {
        label: 'Gender Code',
        value: `${genderLabel} → ${genderCode}`,
        explanation:
          'Gender encoded as integer (1=Male, 2=Female, 3=Other). This is the private input to the Gender ZK circuit.',
      },
    ],
  };
}

module.exports = { preprocessData, computeNameHash, genderToCode };

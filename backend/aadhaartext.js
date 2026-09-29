// Reads Aadhaar fields from OCR text. Pure (no OCR engine), so it can be tested
// on text alone. Handles bilingual cards (Hindi or another regional script next
// to the English text), cards that print only a year of birth, masked Aadhaar
// (XXXX XXXX + last 4 digits), and e-Aadhaar letters that also print a VID.

const { isCalendarDate } = require('../mock-issuer/sign_credential');

// Formats returned for the two card variants, shared with preprocessing and signing.
const YEAR_ONLY_DOB = /^\d{4}$/; // the card prints only a year of birth
const MASKED_AADHAAR = /^XXXX XXXX \d{4}$/; // only the last 4 digits are printed

const DOB_LABELLED =
  /(?:\bDOB\b|\bD\.O\.B\b|Date\s*of\s*Birth|जन्म\s*तिथि)\s*[:\-]?\s*(\d{2})[\/.\-](\d{2})[\/.\-](\d{4})/i;
const YOB_LABELLED = /(?:Year\s*of\s*Birth|\bYOB\b|जन्म\s*वर्ष)\s*[:\-]?\s*(\d{4})\b/i;
const ANY_DATE = /\b(\d{2})\/(\d{2})\/(\d{4})\b/;
// Issue, download and print dates also appear on cards and e-Aadhaar letters.
const NOT_BIRTH_DATE = /issue|download|print|generat|जारी/i;
// Three groups of 4, not part of a longer group such as a 16-digit VID.
const ID_GROUPS = /(?<![\dX]\s?)\b([\dX]{4})\s?([\dX]{4})\s?(\d{4})\b(?!\s?\d)/i;
const VID_LINE = /\bVID\b/i;
const NOT_A_NAME = /GOVERNMENT|INDIA|AADHAAR|UNIQUE|AUTHORITY|ENROL|SPECIMEN|ADDRESS|\bDOB\b|BIRTH|\bMALE\b|FEMALE|\bVID\b/i;

// Labelled full date, then labelled year of birth, then an unlabelled
// DD/MM/YYYY that isn't an issue, download or print date. Returns the line
// index too, since the English name is printed just above it.
function findBirth(lines, now) {
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(DOB_LABELLED);
    if (m) return fullDate(i, m);
  }
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(YOB_LABELLED);
    if (m) {
      const year = Number(m[1]);
      // A misread year would be signed as fact, so implausible ones are unreadable.
      const plausible = year >= 1900 && year <= now.getUTCFullYear();
      return { line: i, dob: plausible ? m[1] : null };
    }
  }
  for (let i = 0; i < lines.length; i++) {
    if (NOT_BIRTH_DATE.test(lines[i]) || VID_LINE.test(lines[i])) continue;
    const m = lines[i].match(ANY_DATE);
    if (m) return fullDate(i, m);
  }
  return null;
}

// A misread like 31/02 is dropped, never passed on as a real DOB.
function fullDate(line, [, dd, mm, yyyy]) {
  const valid = isCalendarDate(Number(yyyy), Number(mm), Number(dd));
  return { line, dob: valid ? `${dd}/${mm}/${yyyy}` : null };
}

// The nearest line above the birth line made (almost) only of Latin letters.
// Regional-script lines, and the noise OCR makes of them, fail that test.
function findName(lines, birthLine) {
  for (let i = birthLine - 1; i >= Math.max(0, birthLine - 3); i--) {
    const line = lines[i];
    if (NOT_A_NAME.test(line)) continue;
    const letters = (line.match(/[A-Za-z]/g) || []).length;
    const visible = line.replace(/\s/g, '').length;
    if (letters < 3 || letters / visible < 0.85) continue;
    return line.replace(/[^A-Za-z\s]/g, ' ').replace(/\s+/g, ' ').trim();
  }
  return null;
}

function findAadhaarNumber(lines) {
  for (const line of lines) {
    if (VID_LINE.test(line)) continue;
    const m = line.match(ID_GROUPS);
    if (!m) continue;
    const [a, b, last4] = [m[1].toUpperCase(), m[2].toUpperCase(), m[3]];
    if (/^\d{4}$/.test(a) && /^\d{4}$/.test(b)) return `${a} ${b} ${last4}`;
    if (a === 'XXXX' && b === 'XXXX') return `XXXX XXXX ${last4}`;
  }
  return null;
}

// English label first; the Hindi word when the English one was misread.
function findGender(text) {
  const english = text.match(/\b(Male|Female|Transgender|Other)\b/i);
  const word = english ? english[1].toLowerCase() : (text.match(/पुरुष|महिला|ट्रांसजेंडर/) || [])[0];
  if (!word) return null;
  if (word === 'male' || word === 'पुरुष') return 'Male';
  if (word === 'female' || word === 'महिला') return 'Female';
  return 'Other';
}

// dob is DD/MM/YYYY or, for a year-only card, YYYY. aadhaarNumber is
// "1234 5678 9012" or, when masked, "XXXX XXXX 9012". Missing fields are null.
function parseAadhaarText(text, { now = new Date() } = {}) {
  const lines = text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  const birth = findBirth(lines, now);
  return {
    rawText: text,
    name: birth ? findName(lines, birth.line) : null,
    dob: birth ? birth.dob : null,
    aadhaarNumber: findAadhaarNumber(lines),
    gender: findGender(text),
  };
}

module.exports = { parseAadhaarText, YEAR_ONLY_DOB, MASKED_AADHAAR };

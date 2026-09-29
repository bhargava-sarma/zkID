// OCR text from synthetic specimen cards (made-up people and numbers), read by
// Tesseract with eng or eng+hin, plus a few hand-written edge cases.
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseAadhaarText } = require('../aadhaartext');

const NOW = new Date('2026-09-28T12:00:00Z');
const parse = (text) => {
  const { rawText, ...fields } = parseAadhaarText(text, { now: NOW });
  return fields;
};

test('English-only card', () => {
  assert.deepEqual(
    parse(['GOVERNMENT OF INDIA', 'Rajesh Kumar', 'DOB: 01/01/1990', 'MALE', '1234 5678 9012'].join('\n')),
    { name: 'Rajesh Kumar', dob: '01/01/1990', aadhaarNumber: '1234 5678 9012', gender: 'Male' }
  );
});

test('bilingual Hindi card read with eng only: Hindi lines are Latin noise', () => {
  const text = String.raw`PEON HOT AWAD. aD Oca TEST
MRA WER
GOVERNMENT OF INDIA
Tha wR
Rajesh Kumar
or ff / DOB: 01/01/1990
U/ MALE
1234 5678 9012
1 Jur, A vga`;
  assert.deepEqual(parse(text), {
    name: 'Rajesh Kumar',
    dob: '01/01/1990',
    aadhaarNumber: '1234 5678 9012',
    gender: 'Male',
  });
});

test('year-of-birth card: the issue date is not taken as the DOB', () => {
  const hin = `SPECIMEN - NOT A VALID ID - zkID OCR TEST
Aadhaar no. issued: 12/05/2012
भारत सरकार
GOVERNMENT OF INDIA
सुनीता देवी
Sunita Devi
जन्म वर्ष / Year of Birth : 1985
महिला / FEMALE
2345 6789 0123
मेरा आधार, मेरी पहचान`;
  const eng = String.raw`SPECIMEN - NOT A VALID ID - zkID OCR TEST
Aadhaar no. issued: 12/05/2012
HRA THR
GOVERNMENT OF INDIA
efter at
Sunita Devi
S91 ay / Year of Birth : 1985
Aft / FEMALE
2345 6789 0123
RT MYR, A ugar`;
  const expected = { name: 'Sunita Devi', dob: '1985', aadhaarNumber: '2345 6789 0123', gender: 'Female' };
  assert.deepEqual(parse(hin), expected);
  assert.deepEqual(parse(eng), expected);
});

test('masked Aadhaar with a VID: neither is read as a full number', () => {
  const text = String.raw`SPECIMEN - NOT A VALID ID - zkID OCR TEST
HRA THR
GOVERNMENT OF INDIA
31 eet
Arjun Mehta
<= fafer / DOB: 12/03/1992
qe% / MALE
XXXX XXXX 4321
VID : 9123 4567 8901 2345
RT MYR, A ugar`;
  assert.deepEqual(parse(text), {
    name: 'Arjun Mehta',
    dob: '12/03/1992',
    aadhaarNumber: 'XXXX XXXX 4321',
    gender: 'Male',
  });
});

test('full number next to a VID, including an unlabelled 16-digit group', () => {
  const lines = ['Rajesh Kumar', 'DOB: 01/01/1990', 'MALE'];
  assert.equal(parse([...lines, '1234 5678 9012', 'VID : 9123 4567 8901 2345'].join('\n')).aadhaarNumber, '1234 5678 9012');
  assert.equal(parse([...lines, '9123 4567 8901 2345', '1234 5678 9012'].join('\n')).aadhaarNumber, '1234 5678 9012');
  assert.equal(parse([...lines, 'VID : 9123 4567 8901 2345'].join('\n')).aadhaarNumber, null);
});

test('bilingual Tamil card read with eng only', () => {
  const text = String.raw`SPECIMEN - NOT A VALID ID - zkID OCR TEST
@pHu sire
GOVERNMENT OF INDIA
STT&S\E [FTL6dT
Karthik Raman
mrs Cs) / DOB: 05/07/1988
ay 650T / MALE
3456 7890 1234
6TEUTS)] LST, 6T60TE)| 6M ITETLD`;
  assert.deepEqual(parse(text), {
    name: 'Karthik Raman',
    dob: '05/07/1988',
    aadhaarNumber: '3456 7890 1234',
    gender: 'Male',
  });
});

test('Hindi labels alone are enough when the English ones are misread', () => {
  const text = ['राजेश कुमार', 'Rajesh Kumar', 'जन्म तिथि : 01/01/1990', 'पुरुष', '1234 5678 9012'].join('\n');
  assert.deepEqual(parse(text), {
    name: 'Rajesh Kumar',
    dob: '01/01/1990',
    aadhaarNumber: '1234 5678 9012',
    gender: 'Male',
  });
});

test('a Hindi line above the DOB is skipped when looking for the name', () => {
  // The English name is damaged, so there is no name rather than a wrong one.
  assert.equal(parse(['GOVERNMENT OF INDIA', 'राजेश कुमार', 'DOB: 01/01/1990'].join('\n')).name, null);
  assert.equal(parse(['Rajesh Kumar', 'राजेश कुमार', 'DOB: 01/01/1990'].join('\n')).name, 'Rajesh Kumar');
});

test('impossible or implausible dates are unreadable', () => {
  assert.equal(parse('Rajesh Kumar\nDOB: 31/02/1990').dob, null);
  assert.equal(parse('Sunita Devi\nYear of Birth : 1850').dob, null);
  assert.equal(parse('Sunita Devi\nYear of Birth : 2031').dob, null);
});

test('an unlabelled date is used only if it is not an issue or download date', () => {
  assert.equal(parse('Rajesh Kumar\n01/01/1990').dob, '01/01/1990');
  assert.equal(parse('Rajesh Kumar\nDownload Date: 01/01/2024').dob, null);
});

// SYNTHETIC Secure QR in the V2 or V5 layout, signed with a caller-supplied TEST key.
// Format-faithful in structure and sizes (see secure-qr.mjs); every value is
// fake and labelled as such. It never verifies against a UIDAI certificate.

import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { FIELDS, bytesToQrText } from './secure-qr.mjs';

// IST wall-clock time as YYYYMMDDHHMMSSsss, as in the reference ID.
function istStamp(date) {
  const ist = new Date(date.getTime() + 330 * 60 * 1000).toISOString();
  return ist.slice(0, 23).replace(/[-:T.]/g, '');
}

// JPEG 2000-shaped bytes: SOC and SIZ markers, random body, EOC marker. The
// body is random, so it contains 0xFF bytes, as real photos do.
export function syntheticPhoto(length = 888) {
  if (length < 6) throw new Error('Photo must be at least 6 bytes.');
  return Buffer.concat([Buffer.from([0xff, 0x4f, 0xff, 0x51]), crypto.randomBytes(length - 6), Buffer.from([0xff, 0xd9])]);
}

export function syntheticFields({ generatedAt = new Date(), ...overrides } = {}) {
  return {
    emailMobileIndicator: '3',
    referenceId: `0000${istStamp(generatedAt)}`,
    name: 'SYNTHETIC TEST PERSON',
    dob: '01-01-1990',
    gender: 'M',
    careOf: 'SYNTHETIC - NOT A REAL AADHAAR',
    district: 'TEST DISTRICT',
    landmark: '',
    house: 'TEST HOUSE',
    location: '',
    pincode: '000000',
    postOffice: 'TEST PO',
    state: 'TEST STATE',
    street: 'TEST STREET',
    subDistrict: 'TEST SUBDISTRICT',
    vtc: 'TEST VTC',
    mobileLast4: '0000',
    mobile: 'xxxxxx0000',
    ...overrides,
  };
}

// Stand-in for the bytes a real V5 code carries after its photo. Their content
// is unknown, so these are random; 0xFF is avoided so they cannot look like the
// photo's end marker.
export function unknownTrailer(length = 27) {
  return Buffer.from(crypto.randomBytes(length).map((b) => (b === 0xff ? 0xfe : b)));
}

export function buildSignedData({ version = 'V2', fields = syntheticFields(), photo = syntheticPhoto(), trailing = Buffer.alloc(0) } = {}) {
  const parts = version === 'V1' ? [] : [Buffer.from(version, 'latin1'), Buffer.from([0xff])];
  for (const name of FIELDS[version] ?? FIELDS.V2) {
    parts.push(Buffer.from(fields[name] ?? '', 'utf8'), Buffer.from([0xff]));
  }
  return Buffer.concat([...parts, photo, trailing]);
}

export function signAndEncode(signedData, privateKey, { compression = 'gzip' } = {}) {
  const signature = crypto.sign('sha256', signedData, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
  const data = Buffer.concat([signedData, signature]);
  const compressed = compression === 'zlib' ? zlib.deflateSync(data) : zlib.gzipSync(data);
  return { text: bytesToQrText(compressed), signedData, signature };
}

export function makeSyntheticSecureQr(privateKey, options = {}) {
  return signAndEncode(buildSignedData(options), privateKey, options);
}

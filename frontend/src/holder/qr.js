// The holder's Secure QR, read and checked on this device. Nothing here sends
// anything: the image, its text and its fields stay in this page's memory.
import jsQR from 'jsqr';
import { decodeSecureQr, findSigner, importRsaKey, parseReferenceId } from '../../../packages/secure-qr/web.mjs';
import { circuitInput } from '../../../packages/circuit/input.mjs';
import registry from '../../../packages/issuer-registry/registry.json' with { type: 'json' };
import { GENDERS, MAX_STATE_BYTES, disclosedFor, revealFor, ruleFailure } from '../../../packages/verifier-sdk/src/rules.ts';
import { HolderError } from './errors.js';

// The local demo's ephemeral test key, compiled in by vite.config.js in demo
// mode (npm run dev:demo, npm run build:demo); null in every other build.
const demoKeys = typeof __ZKID_DEMO_KEYS__ === 'undefined' ? null : __ZKID_DEMO_KEYS__;

// The issuer keys this app accepts: UIDAI's, from the issuer registry, and in a
// demo build the demo's test key. A production build has no test key
// (THREAT_MODEL A1.4).
export async function trustedKeys() {
  const keys = registry.keys.map(({ id, subject, modulus, notBefore, notAfter }) => ({ id, label: subject, modulus, notBefore, notAfter }));
  if (demoKeys) keys.push(...demoKeys);
  return Promise.all(keys.map(async (k) => ({ ...k, cryptoKey: await importRsaKey(k.modulus) })));
}

// The text of the first QR code in an image file.
export async function readQrImage(file) {
  let bitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new HolderError('NOT_AN_IMAGE', 'That file is not an image this browser can read.');
  }
  const canvas = document.createElement('canvas');
  [canvas.width, canvas.height] = [bitmap.width, bitmap.height];
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0);
  const { data, width, height } = ctx.getImageData(0, 0, bitmap.width, bitmap.height);
  const code = jsQR(data, width, height, { inversionAttempts: 'attemptBoth' });
  if (!code) throw new HolderError('NO_QR', 'No QR code found in the image. Use a sharp screenshot of the QR on your e-Aadhaar.');
  return code.data;
}

// Start of the IST hour, in Unix seconds: the circuit's timestamp output.
const istHourStart = (seconds) => Math.floor((seconds + 19800) / 3600) * 3600 - 19800;

// "19 or older on the QR's generation date", computed as the circuit does it
// (Anon Aadhaar's AgeExtractor: completed age > 18), so a proof the verifier
// would refuse is not made at all.
function circuitAgeAbove18(dobBytes, referenceId) {
  const dob = new TextDecoder().decode(dobBytes);
  const m = /^([0-9]{2})-([0-9]{2})-([0-9]{4})$/.exec(dob);
  if (!m) throw new HolderError('UNSUPPORTED_DOB', 'The date of birth in your QR is not in DD-MM-YYYY form, which the circuit cannot read.');
  const [day, month, year] = m.slice(1).map(Number);
  const ref = new TextDecoder().decode(referenceId);
  const [cy, cm, cd] = [ref.slice(4, 8), ref.slice(8, 10), ref.slice(10, 12)].map(Number);
  const age = cy - year - 1 + (cm > month ? 1 : 0) + (cm === month && cd + 1 > day ? 1 : 0);
  return age > 18;
}

const latin1 = (bytes) => String.fromCharCode(...bytes);

// The values the circuit would output for gender, PIN code and state, as
// rules.ts compares them. The circuit reads a 1-byte gender, a 6-byte PIN code
// and a state of at most 31 bytes, revealed or not: any other QR cannot be
// proved at all, so it is refused here, before the download.
function circuitValues(fields, rules) {
  const values = { gender: latin1(fields.gender), pinCode: latin1(fields.pincode), state: latin1(fields.state) };
  if (fields.gender.length !== 1) throw new HolderError('UNSUPPORTED_GENDER', 'The gender in your QR is not one character, which the circuit cannot read.');
  if (fields.pincode.length !== 6 || (rules.pinCode && !/^[0-9]{6}$/.test(values.pinCode))) {
    throw new HolderError('UNSUPPORTED_PIN_CODE', 'The PIN code in your QR is not six digits, which the circuit cannot read.');
  }
  if (fields.state.length > MAX_STATE_BYTES) {
    throw new HolderError('UNSUPPORTED_STATE', `The state in your QR is longer than ${MAX_STATE_BYTES} characters, which the circuit cannot read.`);
  }
  return values;
}

// How the page writes a value or a rule: a PIN code range as 5600xx.
export const shown = { gender: (g) => GENDERS[g] ?? g, pinCode: (p) => p.padEnd(6, 'x'), state: (s) => s };
const RULE_ERRORS = {
  GENDER_NOT_ALLOWED: ['GENDER_NOT_ACCEPTED', 'gender', 'genders'],
  PIN_CODE_NOT_ALLOWED: ['PIN_CODE_NOT_ACCEPTED', 'pinCode', 'PIN codes'],
  STATE_NOT_ALLOWED: ['STATE_NOT_ACCEPTED', 'state', 'states'],
};

// Decodes the QR text and checks it against the trusted keys and the request.
// Returns what the prover needs, and what the page may show: the date, and the
// values the proof will reveal (`disclosed`, only the fields the rules name).
export async function checkQr(text, keys, request, now = Date.now() / 1000) {
  const qr = await decodeSecureQr(text); // throws SecureQrError with a code
  const signer = await findSigner(qr, keys);
  if (!signer) throw new HolderError('UNTRUSTED_QR', 'This QR is not signed by UIDAI (no trusted key verifies it).');
  const { generatedAt } = parseReferenceId(qr.fields.referenceId);
  const hour = istHourStart(generatedAt.getTime() / 1000);
  if (hour < signer.notBefore || hour > signer.notAfter) {
    throw new HolderError('KEY_NOT_VALID', `This QR's date is outside the validity of the key that signed it (${signer.id}).`);
  }
  if (now - hour > request.maxAgeSeconds) {
    throw new HolderError('QR_TOO_OLD', `This QR was generated on ${generatedAt.toDateString()}, which is older than ${request.verifierId} accepts. Download a fresh e-Aadhaar and try again.`);
  }
  const { rules } = request;
  const values = circuitValues(qr.fields, rules);
  if (rules.age19 && !circuitAgeAbove18(qr.fields.dob, qr.fields.referenceId)) {
    throw new HolderError('NOT_19', "Your QR does not show an age of 19 or older on the day it was generated, so the website would refuse the proof. (The circuit's check is \"above 18\", which starts at 19.)");
  }
  const broken = ruleFailure(rules, values);
  if (broken) {
    const [code, field, plural] = RULE_ERRORS[broken];
    throw new HolderError(code, `${request.verifierId} accepts only these ${plural}: ${rules[field].map(shown[field]).join(', ')}. Your QR shows ${shown[field](values[field])}, so nothing was proved or sent.`);
  }
  return { qr, signer, generatedAt, disclosed: disclosedFor(rules, values) };
}

// The circuit input for a checked QR: it reveals what the request's rules name,
// nothing else (throws CircuitError, e.g. PHOTO_TOO_LARGE).
export const inputFor = ({ qr, signer }, publicInputs, rules) => circuitInput(qr, BigInt(`0x${signer.modulus}`), publicInputs, revealFor(rules));

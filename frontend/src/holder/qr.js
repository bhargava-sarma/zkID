// The holder's Secure QR, read and checked on this device. Nothing here sends
// anything: the image, its text and its fields stay in this page's memory.
import jsQR from 'jsqr';
import { decodeSecureQr, findSigner, importRsaKey, parseReferenceId } from '../../../packages/secure-qr/web.mjs';
import { circuitInput } from '../../../packages/circuit/input.mjs';
import registry from '../../../packages/issuer-registry/registry.json' with { type: 'json' };
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

// Decodes the QR text and checks it against the trusted keys and the request.
// Returns what the prover needs and what the page may show (the date only).
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
  if (!circuitAgeAbove18(qr.fields.dob, qr.fields.referenceId)) {
    throw new HolderError('NOT_19', "Your QR does not show an age of 19 or older on the day it was generated, so the website would refuse the proof. (The circuit's check is \"above 18\", which starts at 19.)");
  }
  return { qr, signer, generatedAt };
}

// The circuit input for a checked QR (throws CircuitError, e.g. PHOTO_TOO_LARGE).
export const inputFor = ({ qr, signer }, publicInputs) => circuitInput(qr, BigInt(`0x${signer.modulus}`), publicInputs);

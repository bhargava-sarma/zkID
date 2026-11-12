// The holder's DigiLocker PAN Verification Record (its XML), read and checked
// on this device: DigiLocker's signature against the keys this app trusts, then
// the request's rules, before anything is proved. Nothing here sends anything:
// the file, its text and its values stay in this page's memory.
import registry from '../../../packages/issuer-registry/registry.json' with { type: 'json' };
import { GENDER_VALUES } from '../../../packages/pan/format.mjs';
import { circuitInput } from '../../../packages/pan/input.mjs';
import { istHourToUnix } from '../../../packages/pan/public.mjs';
import { PanError, readRecord, verifiedHour } from '../../../packages/pan/record.mjs';
import { GENDERS, disclosedFor, panDobCutoff, ruleFailure } from '../../../packages/verifier-sdk/src/rules.ts';
import { HolderError } from './errors.js';

// The local demo's ephemeral test key, compiled in by vite.config.js in demo
// mode; null in every other build (THREAT_MODEL A1.4).
const demoKeys = typeof __ZKID_DEMO_KEYS__ === 'undefined' ? null : __ZKID_DEMO_KEYS__;

// The keys this app accepts for a PAN record: DigiLocker's, from the issuer
// registry, and in a demo build the demo's test key.
export function trustedPanKeys() {
  const keys = registry.keys
    .filter((k) => k.document === 'pan')
    .map(({ id, subject, modulus, notBefore, notAfter }) => ({ id, label: `DigiLocker (${subject})`, modulus, notBefore, notAfter }));
  if (demoKeys) keys.push(...demoKeys.filter((k) => k.document === 'pan'));
  return keys;
}

// A record is about 6 KB; anything much larger is not one.
export async function readPanFile(file) {
  if (file.size > 64 * 1024) throw new HolderError('NOT_A_RECORD', 'That file is too large to be a DigiLocker PAN record (about 6 KB).');
  return file.text();
}

const ymd = (ddmmyyyy) => Number(`${ddmmyyyy.slice(6, 10)}${ddmmyyyy.slice(3, 5)}${ddmmyyyy.slice(0, 2)}`);
const ist = (seconds) =>
  new Date(seconds * 1000).toLocaleString('en-IN', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', hour12: false, timeZone: 'Asia/Kolkata' });

// Reads the record and checks it against the trusted keys and the request.
// Returns what the prover needs, and what the page may show: when DigiLocker
// verified the PAN, and the values the proof will reveal (`disclosed`).
export async function checkPan(xml, keys, request, now = Date.now() / 1000) {
  let record;
  try {
    record = await readRecord(xml, keys);
  } catch (err) {
    if (err instanceof PanError) throw new HolderError(err.code, err.message);
    throw err;
  }
  const { signer, values } = record;
  const verifiedAt = istHourToUnix(verifiedHour(values.verifiedOn)); // to the hour, as the circuit outputs it
  if (verifiedAt < signer.notBefore || verifiedAt > signer.notAfter) {
    throw new HolderError('KEY_NOT_VALID', `This record's verification time is outside the validity of the key that signed it (${signer.id}).`);
  }
  if (now - verifiedAt > request.maxAgeSeconds) {
    throw new HolderError(
      'RECORD_TOO_OLD',
      `DigiLocker last verified this PAN on ${ist(verifiedAt)}, which is older than ${request.verifierId} accepts. In DigiLocker, remove the PAN Verification Record and get it again from the Income Tax Department, then download its XML.`,
    );
  }
  const { rules } = request;
  if (rules.age19 && ymd(values.dob) > panDobCutoff(request.issuedAt)) {
    throw new HolderError('NOT_19', 'Your PAN record does not show an age of 19 or older today, so the website would refuse the proof. Nothing was proved or sent.');
  }
  const gender = GENDER_VALUES[values.gender];
  if (ruleFailure(rules, { gender })) {
    throw new HolderError(
      'GENDER_NOT_ACCEPTED',
      `${request.verifierId} accepts only these genders: ${rules.gender.map((g) => GENDERS[g]).join(', ')}. Your record shows ${GENDERS[gender]}, so nothing was proved or sent.`,
    );
  }
  return { record, signer, verifiedAt: new Date(verifiedAt * 1000), disclosed: disclosedFor(rules, { gender }) };
}

// The circuit input for a checked record: the request's age cutoff, and the
// gender revealed only under a gender rule.
export const panInputFor = ({ record }, publicInputs, request) =>
  circuitInput(record, {
    dobCutoff: panDobCutoff(request.issuedAt),
    nullifierSeed: publicInputs.nullifierSeed,
    signalHash: publicInputs.signalHash,
    revealGender: !!request.rules.gender,
  });

// A verifier's rules: what the holder's QR must show. Shared by the verifier
// SDK and the holder app, so it uses only Web APIs.
//
// Anon Aadhaar's circuit outputs "19 or older" as a single bit, but gender, PIN
// code and state as their values. So a rule on one of those three reveals the
// holder's value of that field to the verifier, not only that it passes
// (THREAT_MODEL decision 5). The holder app checks the rules on the device and
// reveals nothing when they fail.

import { RequestError } from './errors.ts';

export const GENDERS = { M: 'Male', F: 'Female', T: 'Transgender' } as const;
export type Gender = keyof typeof GENDERS;

export interface Rules {
  age19: boolean; // the QR must show 19 or older on the day it was generated
  gender?: Gender[]; // accepted genders
  pinCode?: string[]; // accepted PIN codes: 6 digits, or the first 1 to 5 digits of a range
  state?: string[]; // accepted states, as written on Aadhaar; case and spacing are ignored
}

// What a proof revealed for the fields the rules name.
export interface Disclosed {
  gender?: Gender;
  pinCode?: string;
  state?: string;
}

export type RuleFailure = 'GENDER_NOT_ALLOWED' | 'PIN_CODE_NOT_ALLOWED' | 'STATE_NOT_ALLOWED';

// The circuit packs the state into one field element: at most 31 bytes.
export const MAX_STATE_BYTES = 31;
const LIMITS = { gender: 3, pinCode: 100, state: 40 };
const PIN_RULE = /^[1-9][0-9]{0,5}$/;
const STATE_RULE = /^[A-Za-z][A-Za-z .&()'-]*$/;

const normalState = (state: string) => state.trim().replace(/\s+/g, ' ').toLowerCase();

function list<T>(value: unknown, name: keyof typeof LIMITS, valid: (item: unknown) => boolean, key = (item: T) => String(item)): T[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > LIMITS[name]) {
    throw new RequestError('INVALID_REQUEST', `rules.${name} must list 1 to ${LIMITS[name]} values`);
  }
  for (const item of value) {
    if (!valid(item)) throw new RequestError('INVALID_REQUEST', `rules.${name} has an invalid value: ${JSON.stringify(item)}`);
  }
  if (new Set(value.map((item) => key(item as T))).size !== value.length) {
    throw new RequestError('INVALID_REQUEST', `rules.${name} lists a value twice`);
  }
  return value as T[];
}

// Checks rules as a request carries them, and returns them unchanged: the
// signal hash covers them exactly as sent.
export function checkRules(rules: unknown): Rules {
  const r = rules as Rules;
  if (typeof r !== 'object' || r === null || Array.isArray(r)) throw new RequestError('INVALID_REQUEST', 'rules must be an object');
  const unknown = Object.keys(r).filter((k) => !['age19', 'gender', 'pinCode', 'state'].includes(k));
  if (unknown.length) throw new RequestError('INVALID_REQUEST', `unknown rules: ${unknown.join(', ')}`);
  if (typeof r.age19 !== 'boolean') throw new RequestError('INVALID_REQUEST', 'rules.age19 must be true or false');
  if (r.gender !== undefined) list<Gender>(r.gender, 'gender', (g) => typeof g === 'string' && Object.hasOwn(GENDERS, g));
  if (r.pinCode !== undefined) list<string>(r.pinCode, 'pinCode', (p) => typeof p === 'string' && PIN_RULE.test(p));
  if (r.state !== undefined) {
    list<string>(r.state, 'state', (s) => typeof s === 'string' && s.length <= MAX_STATE_BYTES && STATE_RULE.test(s.trim()), normalState);
  }
  return r;
}

// The same rules always give the same text, for the signal hash.
export const canonicalRules = (r: Rules) => JSON.stringify({ age19: r.age19, gender: r.gender ?? null, pinCode: r.pinCode ?? null, state: r.state ?? null });

// Which of the circuit's reveal flags a proof for these rules sets.
export const revealFor = (r: Rules) => ({ ageAbove18: r.age19, gender: !!r.gender, pinCode: !!r.pinCode, state: !!r.state });

// The circuit's outputs (decimal strings) as values; 0 means not revealed.
// Gender is the character's code; the PIN code its six digits as a number; the
// state up to 31 bytes of its name, first byte lowest (Anon Aadhaar's
// ExtractAndPackAsInt).
export function decodeOutputs(signals: { gender: string; pinCode: string; state: string }): Disclosed {
  const out: Disclosed = {};
  const gender = BigInt(signals.gender);
  if (gender !== 0n) out.gender = (gender < 256n ? String.fromCharCode(Number(gender)) : '?') as Gender;
  const pinCode = BigInt(signals.pinCode);
  if (pinCode !== 0n) out.pinCode = pinCode < 1_000_000n ? pinCode.toString().padStart(6, '0') : '?';
  let state = BigInt(signals.state);
  if (state !== 0n) {
    let text = '';
    for (; state > 0n; state >>= 8n) text += String.fromCharCode(Number(state & 0xffn));
    out.state = text;
  }
  return out;
}

// The first rule the values break, if any. A field the rules name but the
// proof did not reveal breaks its rule.
export function ruleFailure(r: Rules, values: Disclosed): RuleFailure | undefined {
  if (r.gender && !(values.gender && r.gender.includes(values.gender))) return 'GENDER_NOT_ALLOWED';
  if (r.pinCode && !(values.pinCode && r.pinCode.some((prefix) => values.pinCode!.startsWith(prefix)))) return 'PIN_CODE_NOT_ALLOWED';
  if (r.state && !(values.state && r.state.some((s) => normalState(s) === normalState(values.state!)))) return 'STATE_NOT_ALLOWED';
  return undefined;
}

// Only the fields the rules name.
export const disclosedFor = (r: Rules, values: Disclosed): Disclosed => ({
  ...(r.gender && { gender: values.gender }),
  ...(r.pinCode && { pinCode: values.pinCode }),
  ...(r.state && { state: values.state }),
});

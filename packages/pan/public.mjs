// What a PAN proof's public inputs mean, without dependencies, for verifiers.

// In the order Barretenberg lists them: the circuit's three public inputs,
// then its five return values.
export const PUBLIC_INPUTS = ['dobCutoff', 'nullifierSeed', 'signalHash', 'pubkeyHash', 'nullifier', 'verifiedHour', 'bornBy', 'gender'];

// The public inputs (32-byte hex strings) by name, as decimal strings.
export function publicValues(publicInputs) {
  return Object.fromEntries(PUBLIC_INPUTS.map((name, i) => [name, BigInt(publicInputs[i]).toString()]));
}

// The start of an IST hour written YYYYMMDDHH (the circuit's verified_hour),
// in Unix seconds.
export function istHourToUnix(hour) {
  const h = String(hour);
  return Date.UTC(Number(h.slice(0, 4)), Number(h.slice(4, 6)) - 1, Number(h.slice(6, 8)), Number(h.slice(8, 10))) / 1000 - 19800;
}

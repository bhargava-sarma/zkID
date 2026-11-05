// The PAN circuit's witness on SYNTHETIC records (synthetic.mjs, TEST key):
// what it outputs, and what it refuses. Needs the compiled circuit (npm run
// build); without it the witness tests are skipped. With PAN_XML=<path to a
// real record, outside git>, also checks that record; nothing of it is printed.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { makeRecord, testIssuer } from '../synthetic.mjs';
import { PanError, circuitInput, expectedOutputs, readRecord } from '../record.mjs';
import { BUILD, close, witness } from './helpers.mjs';

after(close);

const WASM = path.join(BUILD, 'pan-verifier_js', 'pan-verifier.wasm');
const NEEDS_WASM = fs.existsSync(WASM) ? {} : { skip: 'circuit not built: npm run build' };
const issuer = testIssuer();
const other = testIssuer();
const OPTIONS = { dobCutoff: 20071027, nullifierSeed: 1111n, signalHash: 2222n };
const OUTPUTS = ['pubkeyHash', 'nullifier', 'verifiedHour', 'bornBy', 'gender'];

const outputsOf = (w) => Object.fromEntries(OUTPUTS.map((name, i) => [name, w[1 + i]]));
async function fails(input) {
  try {
    await witness(WASM, input);
  } catch {
    return true;
  }
  return false;
}

test('records: a synthetic one reads and checks like a real one; tampered ones are refused before the circuit', async () => {
  const record = readRecord(await makeRecord(issuer));
  assert.equal(record.values.gender, 'MALE');
  const refuses = async (xml, code) => assert.throws(() => readRecord(xml), (e) => e instanceof PanError && e.code === code, code);
  const good = await makeRecord(issuer);
  await refuses(good.replace('SYNTHETIC TEST PERSON', 'SYNTHETIC TEST PERSOM'), 'DIGEST_MISMATCH');
  await refuses(good.replace(/<SignatureValue>./, '<SignatureValue>A'), 'BAD_SIGNATURE');
  await refuses(good.replace('rsa-sha1', 'rsa-sha256'), 'UNSUPPORTED_SIGNED_INFO');
  await refuses(await makeRecord(issuer, { edit: (x) => x.replace('type="PANCR"', 'type="DRVLC"') }), 'UNSUPPORTED_RECORD');
  await refuses(await makeRecord(issuer, { status: 'I' }), 'UNSUPPORTED_RECORD');
  await refuses('not xml <', 'NOT_XML');
});

test('a record meeting the cutoff: outputs as computed outside the circuit, gender only when revealed', NEEDS_WASM, async () => {
  const record = readRecord(await makeRecord(issuer, { dob: '15-06-2000', gender: 'FEMALE' }));
  for (const revealGender of [false, true]) {
    const options = { ...OPTIONS, revealGender };
    const out = outputsOf(await witness(WASM, circuitInput(record, options)));
    assert.deepEqual(out, expectedOutputs(record, options));
  }
  const revealed = outputsOf(await witness(WASM, circuitInput(record, { ...OPTIONS, revealGender: true })));
  assert.equal(revealed.gender, String('F'.charCodeAt(0)));
});

test('the date of birth against the cutoff, to the day', NEEDS_WASM, async () => {
  const record = readRecord(await makeRecord(issuer, { dob: '15-06-2000' }));
  for (const [dobCutoff, bornBy] of [[20000614, '0'], [20000615, '1'], [20000616, '1'], [19991231, '0'], [99991231, '1']]) {
    assert.equal(outputsOf(await witness(WASM, circuitInput(record, { ...OPTIONS, dobCutoff })))['bornBy'], bornBy, String(dobCutoff));
  }
});

test('the nullifier: the same for the same PAN and uid, different for another verifier or another person', NEEDS_WASM, async () => {
  const uid = 'a'.repeat(32);
  const first = readRecord(await makeRecord(issuer, { uid }));
  const again = readRecord(await makeRecord(issuer, { uid, verifiedOn: '01-01-2026 10:00:00' }));
  const someoneElse = readRecord(await makeRecord(issuer, { uid, pan: 'TESTP0001T' }));
  const n = async (record, seed = OPTIONS.nullifierSeed) => outputsOf(await witness(WASM, circuitInput(record, { ...OPTIONS, nullifierSeed: seed }))).nullifier;
  assert.equal(await n(first), await n(again));
  assert.notEqual(await n(first), await n(first, 3333n));
  assert.notEqual(await n(first), await n(someoneElse));
});

test('the circuit refuses a changed record, signature or key, and wrong hints', NEEDS_WASM, async () => {
  const record = readRecord(await makeRecord(issuer));
  const input = circuitInput(record, OPTIONS);
  assert.equal(await fails(input), false, 'positive control');

  const flipped = (at) => ({ ...input, doc: input.doc.map((b, i) => (i === at ? String(Number(b) ^ 1) : b)) });
  for (const at of [5, record.hints.genderAt + 12, record.hints.panAt + 40, record.doc.length - 20]) {
    assert.ok(await fails(flipped(at)), `byte ${at}`);
  }
  const otherKey = readRecord(await makeRecord(other));
  assert.ok(await fails({ ...input, modulus: circuitInput(otherKey, OPTIONS).modulus }), 'another key');
  assert.ok(await fails({ ...input, signature: input.signature.map((l, i) => (i === 3 ? String(BigInt(l) ^ 1n) : l)) }), 'signature');
  // The organization's empty uid="" instead of the person's; gender and <PAN> off by one.
  assert.ok(await fails({ ...input, uidAt: String(input.doc.slice(0, 400).map(Number).findIndex((_, i, d) => String.fromCharCode(...d.slice(i, i + 6)) === ' uid="')) }), 'uid');
  assert.ok(await fails({ ...input, genderAt: String(record.hints.genderAt + 1) }), 'gender');
  assert.ok(await fails({ ...input, panAt: String(record.hints.panAt - 1) }), 'pan');
});

test('the circuit refuses validly signed records outside the layout', NEEDS_WASM, async () => {
  const cases = {
    'another document type': { edit: (x) => x.replace('type="PANCR"', 'type="DRVLC"') },
    'a status other than A': { status: 'I' },
    'two different PAN numbers': { edit: (x) => x.replace('<PAN num="TESTP0000T"', '<PAN num="TESTP9999T"') },
    'another organization': { edit: (x) => x.replace('Income Tax Department', 'Income Tax Departmant') },
  };
  for (const [name, options] of Object.entries(cases)) {
    const xml = await makeRecord(issuer, options);
    assert.throws(() => readRecord(xml), (e) => e instanceof PanError && e.code === 'UNSUPPORTED_RECORD', name);
    assert.ok(await fails(circuitInput(readRecord(xml, { strict: false }), OPTIONS)), name);
  }
});

test('the real record, if given (PAN_XML): read, checked, and accepted by the circuit', { skip: !process.env.PAN_XML && 'PAN_XML not set' }, async () => {
  const record = readRecord(fs.readFileSync(process.env.PAN_XML, 'utf8'));
  if (!fs.existsSync(WASM)) return;
  let out;
  try {
    out = outputsOf(await witness(WASM, circuitInput(record, OPTIONS)));
  } catch {
    assert.fail('the circuit refuses the real record'); // no details: they would carry its values
  }
  assert.ok(JSON.stringify(out) === JSON.stringify(expectedOutputs(record, OPTIONS)), "the circuit's outputs differ from those computed outside it");
});

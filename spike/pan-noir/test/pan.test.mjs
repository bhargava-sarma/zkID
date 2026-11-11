// The Noir PAN circuit on SYNTHETIC records (../pan/synthetic.mjs, TEST key):
// what it returns, and what it refuses. Executing the circuit checks every
// constraint, so these tests need no proof; bench.mjs proves. With
// PAN_XML=<path to a real record, outside git>, also checks that record;
// nothing of it is printed.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Noir } from '@noir-lang/noir_js';
import { makeRecord, testIssuer } from '../../pan/synthetic.mjs';
import { PanError, readRecord } from '../../pan/record.mjs';
import { program } from '../circuit.mjs';
import { expectedOutputs, noirInput, outputsOf } from '../inputs.mjs';

const noir = new Noir(await program());
const issuer = testIssuer();
const other = testIssuer();
const OPTIONS = { dobCutoff: 20071027, nullifierSeed: 1111n, signalHash: 2222n };

const run = async (input) => outputsOf((await noir.execute(input)).returnValue);
// The failure's message, or null if the circuit accepts the input.
async function failure(input) {
  try {
    await noir.execute(input);
    return null;
  } catch (err) {
    return String(err.message);
  }
}

test('a record meeting the cutoff: outputs as computed outside the circuit, gender only when revealed', async () => {
  const record = readRecord(await makeRecord(issuer, { dob: '15-06-2000', gender: 'FEMALE' }));
  for (const revealGender of [false, true]) {
    const options = { ...OPTIONS, revealGender };
    assert.deepEqual(await run(noirInput(record, options)), await expectedOutputs(record, options));
  }
  assert.equal((await run(noirInput(record, { ...OPTIONS, revealGender: true }))).gender, 'F'.charCodeAt(0));
});

test('every gender the record can hold', async () => {
  for (const [gender, letter] of [['MALE', 'M'], ['FEMALE', 'F'], ['TRANSGENDER', 'T']]) {
    const record = readRecord(await makeRecord(issuer, { gender }));
    assert.equal((await run(noirInput(record, { ...OPTIONS, revealGender: true }))).gender, letter.charCodeAt(0), gender);
  }
});

test('the date of birth against the cutoff, to the day', async () => {
  const record = readRecord(await makeRecord(issuer, { dob: '15-06-2000' }));
  for (const [dobCutoff, bornBy] of [[20000614, false], [20000615, true], [20000616, true], [19991231, false], [99991231, true]]) {
    assert.equal((await run(noirInput(record, { ...OPTIONS, dobCutoff }))).bornBy, bornBy, String(dobCutoff));
  }
});

test('the nullifier: the same for the same PAN and uid, different for another verifier or another person', async () => {
  const uid = 'a'.repeat(32);
  const first = readRecord(await makeRecord(issuer, { uid }));
  const again = readRecord(await makeRecord(issuer, { uid, verifiedOn: '01-01-2026 10:00:00' }));
  const someoneElse = readRecord(await makeRecord(issuer, { uid, pan: 'TESTP0001T' }));
  const n = async (record, seed = OPTIONS.nullifierSeed) => (await run(noirInput(record, { ...OPTIONS, nullifierSeed: seed }))).nullifier;
  assert.equal(await n(first), await n(again));
  assert.notEqual(await n(first), await n(first, 3333n));
  assert.notEqual(await n(first), await n(someoneElse));
});

test('the circuit refuses a changed record, signature or key, and wrong hints', async () => {
  const record = readRecord(await makeRecord(issuer));
  const input = noirInput(record, OPTIONS);
  assert.equal(await failure(input), null, 'positive control');

  const flipped = (at) => ({ ...input, doc: input.doc.map((b, i) => (i === at ? b ^ 1 : b)) });
  for (const at of [5, record.hints.genderAt + 12, record.hints.panAt + 40, record.doc.length - 20]) {
    assert.ok(await failure(flipped(at)), `byte ${at}`);
  }
  const otherKey = noirInput(readRecord(await makeRecord(other)), OPTIONS);
  assert.ok(await failure({ ...input, modulus: otherKey.modulus }), 'another key');
  assert.ok(await failure({ ...input, signature: otherKey.signature }), 'another signature');
  // The organization's empty uid="" instead of the person's; gender and <PAN> off by one.
  const organizationUid = Buffer.from(record.doc).indexOf(' uid="');
  assert.ok(organizationUid < record.hints.genderAt);
  assert.ok(await failure({ ...input, uid_at: organizationUid }), 'uid');
  assert.ok(await failure({ ...input, gender_at: record.hints.genderAt + 1 }), 'gender');
  assert.ok(await failure({ ...input, pan_at: record.hints.panAt - 1 }), 'pan');
});

test('the circuit refuses validly signed records outside the layout', async () => {
  const cases = {
    'another document type': { edit: (x) => x.replace('type="PANCR"', 'type="DRVLC"') },
    'a status other than A': { status: 'I' },
    'two different PAN numbers': { edit: (x) => x.replace('<PAN num="TESTP0000T"', '<PAN num="TESTP9999T"') },
    'another organization': { edit: (x) => x.replace('Income Tax Department', 'Income Tax Departmant') },
  };
  for (const [name, options] of Object.entries(cases)) {
    const xml = await makeRecord(issuer, options);
    assert.throws(() => readRecord(xml), (e) => e instanceof PanError && e.code === 'UNSUPPORTED_RECORD', name);
    assert.ok(await failure(noirInput(readRecord(xml, { strict: false }), OPTIONS)), name);
  }
});

test('fields placed after the hashed bytes are refused', async () => {
  // A signed record without its QR image is short enough that bytes after its
  // SHA-256 padding still fall inside the field window. Markup written there
  // is not covered by the signature, so it must not count.
  const record = readRecord(await makeRecord(issuer, { qr: '' }));
  const input = noirInput(record, OPTIONS);
  assert.equal(await failure(input), null, 'positive control');
  assert.ok(input.doc_padded_length + 120 < 1280);
  const fake = Buffer.from(` gender="MALE" uid="${'b'.repeat(32)}"><PAN num="TESTP0000T" verifiedOn="01-01-2030 10:00:00"></PAN>`, 'latin1');
  const doc = [...input.doc];
  const at = input.doc_padded_length + 8;
  doc.splice(at, fake.length, ...fake);
  const forged = { ...input, doc, gender_at: at, uid_at: at + fake.indexOf(' uid="'), pan_at: at + fake.indexOf('<PAN') };
  assert.match(await failure(forged), /the fields must lie in the hashed bytes/);
});

test('the real record, if given (PAN_XML): read, checked, and accepted by the circuit', { skip: !process.env.PAN_XML && 'PAN_XML not set' }, async () => {
  const record = readRecord(fs.readFileSync(process.env.PAN_XML, 'utf8'));
  let outputs;
  try {
    outputs = await run(noirInput(record, OPTIONS));
  } catch {
    assert.fail('the circuit refuses the real record'); // no details: they would carry its values
  }
  const expected = await expectedOutputs(record, OPTIONS);
  assert.ok(Object.keys(expected).every((key) => outputs[key] === expected[key]), "the circuit's outputs differ from those computed outside it");
});

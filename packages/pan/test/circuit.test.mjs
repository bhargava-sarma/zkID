// The pinned circuit (artifacts/pan_verifier.json) on SYNTHETIC records: what
// it outputs, and what it refuses. Executing it checks every constraint, so
// these tests need no proof (prove.test.mjs proves). With PAN_XML=<paths of
// real records, outside git, separated by ':'>, also checks those; nothing of
// them is printed.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Noir } from '@noir-lang/noir_js';
import program from '../artifacts/pan_verifier.json' with { type: 'json' };
import { circuitInput, expectedOutputs } from '../input.mjs';
import { readRecord } from '../record.mjs';
import { makeRecord, testIssuer, testKey } from '../synthetic.mjs';

const noir = new Noir(program);
const issuer = testIssuer();
const keys = [testKey(issuer)];
const other = testIssuer();
const OPTIONS = { dobCutoff: 20071027, nullifierSeed: 1111n, signalHash: 2222n };
const OUTPUTS = ['pubkeyHash', 'nullifier', 'verifiedHour', 'bornBy', 'gender'];

const read = async (options, trusted = keys, strict = true) => readRecord(await makeRecord(trusted === keys ? issuer : other, options), trusted, { strict });
// The circuit's return values, as decimal strings.
async function run(input) {
  const { returnValue } = await noir.execute(input);
  return Object.fromEntries(OUTPUTS.map((name, i) => [name, BigInt(returnValue[i]).toString()]));
}
// The failure's message, or null if the circuit accepts the input.
async function failure(input) {
  try {
    await noir.execute(input);
    return null;
  } catch (err) {
    return String(err.message);
  }
}

test('outputs equal what input.mjs computes outside the circuit, gender only when revealed', async () => {
  const record = await read({ dob: '15-06-2000', gender: 'FEMALE' });
  for (const revealGender of [false, true]) {
    const options = { ...OPTIONS, revealGender };
    assert.deepEqual(await run(circuitInput(record, options)), expectedOutputs(record, options));
  }
});

test('every gender the record can hold', async () => {
  for (const [gender, letter] of [['MALE', 'M'], ['FEMALE', 'F'], ['TRANSGENDER', 'T']]) {
    const output = (await run(circuitInput(await read({ gender }), { ...OPTIONS, revealGender: true }))).gender;
    assert.equal(output, String(letter.charCodeAt(0)), gender);
  }
});

test('the date of birth against the cutoff, to the day', async () => {
  const record = await read({ dob: '15-06-2000' });
  for (const [dobCutoff, bornBy] of [[20000614, '0'], [20000615, '1'], [20000616, '1'], [19991231, '0'], [99991231, '1']]) {
    assert.equal((await run(circuitInput(record, { ...OPTIONS, dobCutoff }))).bornBy, bornBy, String(dobCutoff));
  }
});

test('the nullifier: the same for the same PAN and uid, different for another verifier or another person', async () => {
  const uid = 'a'.repeat(32);
  const n = async (record, seed = OPTIONS.nullifierSeed) => (await run(circuitInput(record, { ...OPTIONS, nullifierSeed: seed }))).nullifier;
  const first = await read({ uid });
  assert.equal(await n(first), await n(await read({ uid, verifiedOn: '01-01-2026 10:00:00' })));
  assert.notEqual(await n(first), await n(first, 3333n));
  assert.notEqual(await n(first), await n(await read({ uid, pan: 'TESTP0001T' })));
});

test('the circuit refuses a changed record, signature or key, and wrong hints', async () => {
  const record = await read({});
  const input = circuitInput(record, OPTIONS);
  assert.equal(await failure(input), null, 'positive control');
  const flipped = (at) => ({ ...input, doc: input.doc.map((b, i) => (i === at ? b ^ 1 : b)) });
  for (const at of [5, record.hints.genderAt + 12, record.hints.panAt + 40, record.doc.length - 20]) {
    assert.ok(await failure(flipped(at)), `byte ${at}`);
  }
  const otherInput = circuitInput(await read({}, [testKey(other)]), OPTIONS);
  assert.ok(await failure({ ...input, modulus: otherInput.modulus }), 'another key');
  assert.ok(await failure({ ...input, signature: otherInput.signature }), 'another signature');
  const organizationUid = Buffer.from(record.doc).indexOf(' uid="'); // the issuer's empty uid="", not the person's
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
    assert.ok(await failure(circuitInput(await read(options, keys, false), OPTIONS)), name);
  }
});

test('attributes written after the hashed bytes of a short record are refused', async () => {
  // Without its QR image a signed record is short enough that bytes after its
  // SHA-256 padding still fall inside the field window. They are not signed.
  const input = circuitInput(await read({ qr: '' }), OPTIONS);
  assert.equal(await failure(input), null, 'positive control');
  const fake = Buffer.from(` gender="MALE" uid="${'b'.repeat(32)}"><PAN num="TESTP0000T" verifiedOn="01-01-2030 10:00:00"></PAN>`, 'latin1');
  const at = input.doc_padded_length + 8;
  assert.ok(at + fake.length < 1280);
  const doc = [...input.doc];
  doc.splice(at, fake.length, ...fake);
  const forged = { ...input, doc, gender_at: at, uid_at: at + fake.indexOf(' uid="'), pan_at: at + fake.indexOf('<PAN') };
  assert.match(await failure(forged), /the fields must lie in the hashed bytes/);
});

test('real records, if given (PAN_XML): read, checked, and accepted by the circuit', { skip: !process.env.PAN_XML && 'PAN_XML not set' }, async () => {
  for (const file of process.env.PAN_XML.split(path.delimiter)) {
    // Signed by whichever key the record carries: this test is about the circuit, not trust.
    const xml = fs.readFileSync(file, 'utf8');
    const modulus = new (await import('node:crypto')).X509Certificate(Buffer.from(/<X509Certificate>([^<]+)</.exec(xml)[1].replace(/\s+/g, ''), 'base64')).publicKey.export({ format: 'jwk' }).n;
    const record = await readRecord(xml, [{ id: 'carried', modulus: Buffer.from(modulus, 'base64url').toString('hex') }]);
    let outputs;
    try {
      outputs = await run(circuitInput(record, OPTIONS));
    } catch {
      assert.fail('the circuit refuses a real record'); // no details: they would carry its values
    }
    const expected = expectedOutputs(record, OPTIONS);
    assert.ok(OUTPUTS.every((key) => outputs[key] === expected[key]), "the circuit's outputs differ from those computed outside it");
  }
});

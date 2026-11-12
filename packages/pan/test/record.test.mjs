// record.mjs on SYNTHETIC records (synthetic.mjs, TEST keys): what it reads,
// and each refusal, with its code, before anything reaches the circuit.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PanError, readRecord, verifiedHour } from '../record.mjs';
import { istHourToUnix } from '../public.mjs';
import { makeRecord, testIssuer, testKey } from '../synthetic.mjs';

const issuer = testIssuer();
const keys = [testKey(issuer)];
const refuses = async (xml, code, trusted = keys) =>
  assert.rejects(readRecord(xml, trusted), (e) => e instanceof PanError && e.code === code, code);

test('a synthetic record reads: its signer and values', async () => {
  const xml = await makeRecord(issuer, { dob: '15-06-2000', gender: 'FEMALE', verifiedOn: '05-11-2026 13:33:17', uid: 'c'.repeat(32) });
  const record = await readRecord(xml, keys);
  assert.equal(record.signer.id, 'test-pan-key');
  assert.deepEqual(record.values, { pan: 'TESTP0000T', dob: '15-06-2000', gender: 'FEMALE', uid: 'c'.repeat(32), verifiedOn: '05-11-2026 13:33:17' });
  assert.equal(verifiedHour(record.values.verifiedOn), 2026110513);
  assert.equal(istHourToUnix(2026110513), Date.parse('2026-11-05T13:00:00+05:30') / 1000);
});

test('refused before the circuit: a changed record, another key, another signature scheme, and what is not a record', async () => {
  const good = await makeRecord(issuer);
  await refuses(good.replace('SYNTHETIC TEST PERSON', 'SYNTHETIC TEST PERSOM'), 'DIGEST_MISMATCH');
  await refuses(good.replace(/<SignatureValue>./, '<SignatureValue>A'), 'UNTRUSTED_RECORD');
  await refuses(good, 'UNTRUSTED_RECORD', [testKey(testIssuer())]);
  await refuses(good, 'UNTRUSTED_RECORD', []);
  await refuses(good.replace('rsa-sha1', 'rsa-sha256'), 'UNSUPPORTED_SIGNATURE');
  await refuses(good.replace('xml-exc-c14n#', 'xml-c14n-20010315'), 'UNSUPPORTED_SIGNATURE');
  await refuses('not xml <', 'NOT_XML');
  await refuses('<!DOCTYPE x [<!ENTITY e "x">]><Certificate/>', 'NOT_XML');
  await refuses('<Certificate/>', 'NOT_A_RECORD');
  await refuses(good.replace('<Certificate ', '<Certificat ').replace('</Certificate>', '</Certificat>'), 'NOT_A_RECORD');
});

test('refused before the circuit: validly signed records outside the layout it reads', async () => {
  const cases = {
    'another document type': { edit: (x) => x.replace('type="PANCR"', 'type="DRVLC"') },
    'a status other than A': { status: 'I' },
    'two different PAN numbers': { edit: (x) => x.replace('<PAN num="TESTP0000T"', '<PAN num="TESTP9999T"') },
    'another organization': { edit: (x) => x.replace('Income Tax Department', 'Income Tax Departmant') },
    'another gender value': { gender: 'OTHER' },
    'a uid that is not hex': { uid: 'Z'.repeat(32) },
  };
  for (const [name, options] of Object.entries(cases)) {
    await refuses(await makeRecord(issuer, options), 'UNSUPPORTED_RECORD');
    assert.ok(await readRecord(await makeRecord(issuer, options), keys, { strict: false }), `${name}: reads without the layout checks`);
  }
  await refuses(await makeRecord(issuer, { qr: 'A'.repeat(4000) }), 'RECORD_TOO_LONG');
  // XML a record never holds, refused as it is canonicalized, before any digest.
  await refuses((await makeRecord(issuer)).replace('<IssuedBy>', '<IssuedBy><x:Y xmlns:x="urn:x"/>'), 'UNSUPPORTED_RECORD');
});

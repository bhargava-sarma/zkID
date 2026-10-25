// inspect-qr.mjs must describe unknown layouts correctly and never print values.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { kind, scanFields } from '../inspect-qr.mjs';
import { decodeEnvelope } from '../secure-qr.mjs';
import { buildSignedData, makeSyntheticSecureQr, signAndEncode, syntheticFields, syntheticPhoto } from '../synthetic.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const SAMPLE = path.join(here, '..', 'local', 'uidai-official-sample-v1.txt');
const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'inspect-'));

test('field kinds describe without revealing', () => {
  assert.equal(kind(Buffer.from('')), 'empty');
  assert.equal(kind(Buffer.from('V5')), 'version marker');
  assert.equal(kind(Buffer.from('560099')), '6 digits');
  assert.equal(kind(Buffer.from('13-07-1987')), 'date pattern DD-MM-YYYY');
  assert.equal(kind(Buffer.from('M')), 'one letter');
  assert.equal(kind(Buffer.from('Asha Rao')), '8 bytes, letters and spaces');
  assert.equal(kind(Buffer.from('रमेश', 'utf8')), '12 bytes, UTF-8 text with non-ASCII characters');
  assert.equal(kind(Buffer.from([0xc3, 0x28])), '2 bytes, binary');
});

test('a synthetic V2 code: version marker, 17 fields, then the photo', () => {
  const { fields, image } = scanFields(decodeEnvelope(makeSyntheticSecureQr(keys.privateKey).text).signedData);
  assert.equal(fields.length, 18);
  assert.equal(kind(fields[0].bytes), 'version marker');
  assert.deepEqual([image.type, image.length, image.after], ['JPEG 2000 codestream', 888, 0]);
});

test('an unknown layout with an extra local-language field and a JPEG photo is described', () => {
  const fields = { ...syntheticFields(), mobileLast4: 'रमेश' };
  const jpegPhoto = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), crypto.randomBytes(500), Buffer.from([0xff, 0xd9])]);
  const signed = buildSignedData({ version: 'V5', fields, photo: jpegPhoto });
  const { fields: found, image } = scanFields(decodeEnvelope(signAndEncode(signed, keys.privateKey).text).signedData);
  assert.equal(found.length, 18);
  assert.match(kind(found[17].bytes), /UTF-8/);
  assert.deepEqual([image.type, image.length, image.after], ['JPEG', 506, 0]);
});

test('UIDAI official sample: 16 fields, JPEG 2000 at 177, 64 bytes after', { skip: fs.existsSync(SAMPLE) ? false : 'run npm run fetch-uidai-sample first' }, () => {
  const { fields, image } = scanFields(decodeEnvelope(fs.readFileSync(SAMPLE, 'utf8')).signedData);
  assert.equal(fields.length, 16);
  assert.deepEqual([image.type, image.offset, image.length, image.after], ['JPEG 2000 codestream', 177, 888, 64]);
});

test('privacy negative control: neither tool prints any field value', () => {
  const markers = {
    name: 'ZZMARKERNAME',
    dob: '13-07-1987',
    careOf: 'ZZMARKERCAREOF',
    pincode: '560099',
    vtc: 'ZZMARKERVTC',
    mobileLast4: '9876',
    referenceId: '4321' + '20261020123456789',
  };
  const file = path.join(dir, 'qr.txt');
  fs.writeFileSync(file, makeSyntheticSecureQr(keys.privateKey, { version: 'V5', fields: syntheticFields(markers) }).text);
  const run = (script) => {
    try {
      return execFileSync(process.execPath, [path.join(here, '..', script), file], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      return `${err.stdout}${err.stderr}`;
    }
  };
  const outputs = [run('inspect-qr.mjs'), run('verify-qr.mjs')];
  assert.match(outputs[0], /fields      18 before the photo/);
  for (const out of outputs) {
    for (const value of Object.values(markers)) assert.equal(out.includes(value), false, `printed "${value}"`);
    assert.equal(out.includes('4321'), false, 'printed the Aadhaar last-4 digits');
  }
});

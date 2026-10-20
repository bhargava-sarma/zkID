// Fails if any tracked file holds private key material.
// Run: node --test "tools/repo-checks/*.test.mjs"
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
// Built from parts so this file does not match itself.
const MARKER = new RegExp(['-----BEGIN', '(?:[A-Z0-9]+ )*PRIVATE KEY-----'].join(' '));
const KEY_FILE = /\.(pem|key|p12|pfx)$/i;

function findings(files, read) {
  return files.filter((file) => KEY_FILE.test(file) || MARKER.test(read(file)));
}

const tracked = () =>
  execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8' })
    .split('\0')
    .filter(Boolean)
    .filter((file) => fs.existsSync(path.join(root, file)));

test('no tracked file is a key file or contains a PEM private key', () => {
  assert.deepEqual(findings(tracked(), (file) => fs.readFileSync(path.join(root, file), 'latin1')), []);
});

test('negative control: the check flags key files and embedded PEM private keys', () => {
  const pem = ['-----BEGIN', 'RSA PRIVATE KEY-----\nMIIE...\n-----END', 'RSA PRIVATE KEY-----'].join(' ');
  const files = { 'a.pem': '', 'b.json': `{"k":"${pem}"}`, 'c.js': 'clean', 'd.json': pem.replace(/RSA /g, '') };
  assert.deepEqual(findings(Object.keys(files), (f) => files[f]), ['a.pem', 'b.json', 'd.json']);
});

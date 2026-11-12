// Run: npm test (in packages/issuer-registry).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { RegistryError, checkRegistry, findKey, productionRegistry, spkiSha256, testRegistry } from '../index.ts';
import { entries } from '../build.mjs';
import { keyHash } from '../../circuit/index.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const throwsCode = (fn: () => unknown, code: string) =>
  assert.throws(fn, (err: unknown) => err instanceof RegistryError && err.code === code, `expected ${code}`);
const freshTestKey = () => {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { publicKey, keyHash: keyHash(publicKey) as string };
};

test("registry.json is what build.mjs makes from the UIDAI certificates and DigiLocker's keys", () => {
  const file = JSON.parse(fs.readFileSync(new URL('../registry.json', import.meta.url), 'utf8'));
  assert.deepEqual(file.keys, entries());
});

test("the 2021 key's hash equals the one Anon Aadhaar's SDK pins (an independent check of keyHash)", () => {
  const ds05 = productionRegistry().keys.find((k) => k.id === 'uidai-ds-05_2021-2024');
  // anon-aadhaar packages/core/src/constants.ts at 4dad918
  assert.equal(ds05?.keyHash, '18063425702624337643644061197836918910810808173893535653269228433734128853484');
});

test("production registry: the four UIDAI keys and DigiLocker's; DS 06 and DigiLocker's key cover November 2026", () => {
  const registry = productionRegistry();
  assert.equal(registry.keys.length, 5);
  assert.ok(registry.keys.every((k) => !k.test));
  assert.deepEqual(registry.keys.map((k) => `${k.issuer}/${k.document}`), ['UIDAI/aadhaar', 'UIDAI/aadhaar', 'UIDAI/aadhaar', 'UIDAI/aadhaar', 'DigiLocker/pan']);
  const november2026 = Date.parse('2026-11-11T00:00:00Z') / 1000;
  for (const id of ['uidai-ds-06_2026-2029', 'digilocker-ds-2026-2029']) {
    const key = registry.keys.find((k) => k.id === id);
    assert.ok(key && key.notBefore <= november2026 && november2026 <= key.notAfter, id);
    assert.equal(findKey(registry, key.keyHash, key.document), key);
  }
  assert.equal(findKey(registry, '1'), undefined);
});

test("a key is found only for its own document: a PAN key's hash names no Aadhaar key, and the other way round", () => {
  const registry = productionRegistry();
  const pan = registry.keys.find((k) => k.document === 'pan')!;
  const aadhaar = registry.keys.find((k) => k.document === 'aadhaar')!;
  assert.equal(findKey(registry, pan.keyHash, 'aadhaar'), undefined);
  assert.equal(findKey(registry, pan.keyHash), undefined, 'the default document is aadhaar');
  assert.equal(findKey(registry, aadhaar.keyHash, 'pan'), undefined);
  // The same RSA key, trusted for both documents, is two entries with two hashes.
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const both = testRegistry([{ publicKey, id: 'q' }, { publicKey, id: 'p', document: 'pan' }]);
  assert.notEqual(both.keys[0].keyHash, both.keys[1].keyHash);
  assert.equal(findKey(both, both.keys[1].keyHash, 'pan')?.id, 'p');
});

test('T1.5: a test key in a production registry is refused, and the check CLI fails the build', () => {
  const testKeys = testRegistry([freshTestKey(), { ...freshTestKey(), keyHash: undefined, document: 'pan' }]).keys;
  const mixed = [...productionRegistry().keys, ...testKeys];
  throwsCode(() => checkRegistry({ production: true, keys: mixed }), 'TEST_KEY_IN_PRODUCTION');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkid-registry-'));
  try {
    const file = path.join(dir, 'registry.json');
    fs.writeFileSync(file, JSON.stringify({ keys: mixed }));
    const exitCode = (args: string[]) => {
      try {
        execFileSync(process.execPath, [path.join(here, '..', 'check.ts'), ...args], { stdio: 'pipe' });
        return 0;
      } catch (err) {
        return (err as { status: number }).status;
      }
    };
    assert.equal(exitCode([file, '--production']), 1);
    assert.equal(exitCode([file]), 0, 'test keys are allowed outside production');
    assert.equal(exitCode([path.join(here, '..', 'registry.json'), '--production']), 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a compromised key (the v1 demo key) is refused in any registry', () => {
  const { keys } = JSON.parse(fs.readFileSync(new URL('../../../security/compromised-keys.json', import.meta.url), 'utf8'));
  const v1 = keys[0];
  const publicKey = crypto.createPublicKey({
    key: { kty: 'RSA', n: Buffer.from(v1.modulus_hex, 'hex').toString('base64url'), e: 'AQAB' },
    format: 'jwk',
  });
  assert.equal(spkiSha256(publicKey), v1.spki_sha256);
  throwsCode(() => testRegistry([{ publicKey, keyHash: keyHash(publicKey) as string }]), 'COMPROMISED_KEY');
});

test('malformed and duplicate entries are refused', () => {
  const [entry] = testRegistry([freshTestKey()]).keys;
  throwsCode(() => checkRegistry({ production: false, keys: [{ ...entry, notAfter: entry.notBefore }] }), 'BAD_ENTRY');
  throwsCode(() => checkRegistry({ production: false, keys: [{ ...entry, keyHash: '0x12' }] }), 'BAD_ENTRY');
  throwsCode(() => checkRegistry({ production: false, keys: [{ ...entry, keyHash: (BigInt(entry.keyHash) + 1n).toString() }] }), 'BAD_ENTRY');
  throwsCode(() => checkRegistry({ production: false, keys: [entry, { ...entry, id: 'again' }] }), 'DUPLICATE_KEY');
  throwsCode(() => checkRegistry({ production: false, keys: [{ ...entry, document: 'passport' as 'pan' }] }), 'BAD_ENTRY');
  throwsCode(() => checkRegistry({ production: false, keys: [{ ...entry, document: 'pan' }] }), 'BAD_ENTRY'); // an Aadhaar key hash, called a PAN one
});

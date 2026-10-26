// Trusted issuer keys for zkID verifiers. Each entry is the circuit's key hash
// (its pubkeyHash output) for one UIDAI Secure QR signing key, with the key's
// validity window. A production registry holds only the UIDAI keys in
// registry.json: test keys are refused there (THREAT_MODEL A1.4), and keys
// listed in security/compromised-keys.json are refused everywhere.
//
// Every failure throws a RegistryError with a code.

import crypto from 'node:crypto';
import fs from 'node:fs';

export interface IssuerKey {
  id: string;
  issuer: string;
  keyHash: string; // the circuit's pubkeyHash for this key, decimal
  notBefore: number; // Unix seconds
  notAfter: number;
  spkiSha256: string;
  test?: boolean;
}

export interface Registry {
  production: boolean;
  keys: IssuerKey[];
}

export type RegistryErrorCode = 'TEST_KEY_IN_PRODUCTION' | 'COMPROMISED_KEY' | 'BAD_ENTRY' | 'DUPLICATE_KEY';

export class RegistryError extends Error {
  code: RegistryErrorCode;
  constructor(code: RegistryErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'RegistryError';
    this.code = code;
  }
}

const REGISTRY_FILE = new URL('./registry.json', import.meta.url);
const COMPROMISED_FILE = new URL('../../security/compromised-keys.json', import.meta.url);

export const spkiSha256 = (publicKey: crypto.KeyObject): string =>
  crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');

function compromisedSpkiHashes(): Set<string> {
  const { keys } = JSON.parse(fs.readFileSync(COMPROMISED_FILE, 'utf8')) as { keys: { spki_sha256: string }[] };
  return new Set(keys.map((k) => k.spki_sha256));
}

// Returns the registry if it may be used; throws otherwise.
export function checkRegistry(registry: Registry): Registry {
  const compromised = compromisedSpkiHashes();
  const seen = new Set<string>();
  for (const key of registry.keys) {
    if (!/^[0-9]+$/.test(key.keyHash) || !(key.notBefore < key.notAfter) || !/^[0-9a-f]{64}$/.test(key.spkiSha256)) {
      throw new RegistryError('BAD_ENTRY', `${key.id}: needs a decimal keyHash, notBefore < notAfter and an SPKI SHA-256.`);
    }
    if (compromised.has(key.spkiSha256)) {
      throw new RegistryError('COMPROMISED_KEY', `${key.id} is listed in security/compromised-keys.json.`);
    }
    if (registry.production && key.test) {
      throw new RegistryError('TEST_KEY_IN_PRODUCTION', `${key.id} is a test key.`);
    }
    if (seen.has(key.keyHash)) throw new RegistryError('DUPLICATE_KEY', `${key.id}: key hash listed twice.`);
    seen.add(key.keyHash);
  }
  return registry;
}

// The UIDAI keys in registry.json (built by build.mjs from packages/secure-qr/certs).
export function productionRegistry(file: URL | string = REGISTRY_FILE): Registry {
  const { keys } = JSON.parse(fs.readFileSync(file, 'utf8')) as { keys: IssuerKey[] };
  return checkRegistry({ production: true, keys });
}

export interface TestKey {
  publicKey: crypto.KeyObject;
  keyHash: string; // from keyHash() in packages/circuit
  id?: string;
  notBefore?: number;
  notAfter?: number;
}

// A registry of test keys, for tests and the local demo only.
export function testRegistry(keys: TestKey[]): Registry {
  return checkRegistry({
    production: false,
    keys: keys.map((k, i) => ({
      id: k.id ?? `test-key-${i + 1}`,
      issuer: 'TEST (ephemeral key, not UIDAI)',
      keyHash: k.keyHash,
      notBefore: k.notBefore ?? 0,
      notAfter: k.notAfter ?? 2 ** 32,
      spkiSha256: spkiSha256(k.publicKey),
      test: true,
    })),
  });
}

export const findKey = (registry: Registry, keyHash: string): IssuerKey | undefined =>
  registry.keys.find((k) => k.keyHash === keyHash);

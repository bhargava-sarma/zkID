// Trusted issuer keys for zkID verifiers. Each entry is one signing key for one
// kind of document, as the hash that document's circuit outputs for it (its
// pubkeyHash), with the key's validity window: UIDAI's Secure QR keys for
// Aadhaar, DigiLocker's record keys for PAN. A production registry holds only
// the keys in registry.json: test keys are refused there (THREAT_MODEL A1.4),
// and keys listed in security/compromised-keys.json are refused everywhere.
//
// Every failure throws a RegistryError with a code.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { keyHashFromModulus } from '../circuit/input.mjs';
import { panKeyHash } from '../pan/keyhash.mjs';

// The credentials zkID proves: an Aadhaar Secure QR, or a DigiLocker PAN
// Verification Record.
export const DOCUMENTS = ['aadhaar', 'pan'] as const;
export type Document = (typeof DOCUMENTS)[number];

// Each circuit's key hash for an RSA modulus (hex): Anon Aadhaar's Poseidon
// over 121-bit limbs, and the PAN circuit's Poseidon2 over 120-bit limbs.
export const KEY_HASH: Record<Document, (modulusHex: string) => string> = {
  aadhaar: (modulusHex) => keyHashFromModulus(BigInt(`0x${modulusHex}`)),
  pan: (modulusHex) => panKeyHash(modulusHex),
};

export interface IssuerKey {
  id: string;
  issuer: string;
  document: Document;
  keyHash: string; // the document's circuit's pubkeyHash for this key, decimal
  modulus: string; // RSA modulus, hex (e = 65537); the holder app needs it
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
    if (!DOCUMENTS.includes(key.document)) throw new RegistryError('BAD_ENTRY', `${key.id}: document must be one of ${DOCUMENTS.join(', ')}.`);
    if (!/^[0-9]+$/.test(key.keyHash) || !(key.notBefore < key.notAfter) || !/^[0-9a-f]{64}$/.test(key.spkiSha256) || !/^[0-9a-f]{512}$/.test(key.modulus)) {
      throw new RegistryError('BAD_ENTRY', `${key.id}: needs a decimal keyHash, notBefore < notAfter, an SPKI SHA-256 and a 2048-bit modulus.`);
    }
    if (KEY_HASH[key.document](key.modulus) !== key.keyHash) {
      throw new RegistryError('BAD_ENTRY', `${key.id}: keyHash does not match the modulus.`);
    }
    if (compromised.has(key.spkiSha256)) {
      throw new RegistryError('COMPROMISED_KEY', `${key.id} is listed in security/compromised-keys.json.`);
    }
    if (registry.production && key.test) {
      throw new RegistryError('TEST_KEY_IN_PRODUCTION', `${key.id} is a test key.`);
    }
    if (seen.has(`${key.document}:${key.keyHash}`)) throw new RegistryError('DUPLICATE_KEY', `${key.id}: key hash listed twice.`);
    seen.add(`${key.document}:${key.keyHash}`);
  }
  return registry;
}

// The UIDAI and DigiLocker keys in registry.json (built by build.mjs).
export function productionRegistry(file: URL | string = REGISTRY_FILE): Registry {
  const { keys } = JSON.parse(fs.readFileSync(file, 'utf8')) as { keys: IssuerKey[] };
  return checkRegistry({ production: true, keys });
}

export interface TestKey {
  publicKey: crypto.KeyObject;
  document?: Document; // default aadhaar
  keyHash?: string; // default: KEY_HASH[document] of the key's modulus
  id?: string;
  notBefore?: number;
  notAfter?: number;
}

// A registry of test keys, for tests and the local demo only.
export function testRegistry(keys: TestKey[]): Registry {
  return checkRegistry({
    production: false,
    keys: keys.map((k, i) => {
      const document = k.document ?? 'aadhaar';
      const modulus = Buffer.from(k.publicKey.export({ format: 'jwk' }).n as string, 'base64url').toString('hex');
      return {
        id: k.id ?? `test-key-${i + 1}`,
        issuer: `TEST (ephemeral key, not ${document === 'pan' ? 'DigiLocker' : 'UIDAI'})`,
        document,
        keyHash: k.keyHash ?? KEY_HASH[document](modulus),
        modulus,
        notBefore: k.notBefore ?? 0,
        notAfter: k.notAfter ?? 2 ** 32,
        spkiSha256: spkiSha256(k.publicKey),
        test: true,
      };
    }),
  });
}

// The key a proof of this document names, if the registry trusts it.
export const findKey = (registry: Registry, keyHash: string, document: Document = 'aadhaar'): IssuerKey | undefined =>
  registry.keys.find((k) => k.document === document && k.keyHash === keyHash);

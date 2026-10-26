// UIDAI Secure QR certificates from certs/, checked against certs/registry.json.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'certs');

export function loadUidaiCerts() {
  const { certificates } = JSON.parse(fs.readFileSync(path.join(DIR, 'registry.json'), 'utf8'));
  return certificates.map((meta) => {
    const cert = new crypto.X509Certificate(fs.readFileSync(path.join(DIR, meta.file)));
    const fingerprint = cert.fingerprint256.replace(/:/g, '').toLowerCase();
    if (fingerprint !== meta.cert_sha256) {
      throw new Error(`${meta.file}: fingerprint ${fingerprint} does not match registry.json (${meta.cert_sha256}).`);
    }
    return { label: meta.file, cert, meta };
  });
}

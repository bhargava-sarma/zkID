#!/usr/bin/env node
// Prepares the local demo: an ephemeral TEST issuer key, and a SYNTHETIC Secure
// QR (V5 layout, fake values) signed with it, as a PNG to use in the holder app.
// The private key exists only while this script runs. Writes, gitignored:
//   apps/demo-rp/.demo/test-issuer.json   public key, for the demo verifiers and
//                                         a demo build of the holder app
//   apps/demo-rp/.demo/synthetic-qr.png   the QR image
// Usage: node setup-demo.mjs

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import QRCode from 'qrcode';
import { keyHash } from '../../packages/circuit/index.mjs';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../../packages/secure-qr/synthetic.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const demoDir = path.join(here, '.demo');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const { text } = makeSyntheticSecureQr(privateKey, {
  version: 'V5',
  photo: syntheticPhoto(900),
  trailing: unknownTrailer(27),
  fields: syntheticFields({ generatedAt: new Date() }),
});
const issuer = {
  note: 'TEST issuer for the local demo: an ephemeral key, NOT UIDAI. Never trust it outside the demo.',
  keys: [
    {
      id: 'demo-test-key',
      label: 'TEST ISSUER (local demo, not UIDAI)',
      modulus: Buffer.from(publicKey.export({ format: 'jwk' }).n, 'base64url').toString('hex'),
      keyHash: keyHash(publicKey),
      notBefore: 0,
      notAfter: 2 ** 32,
    },
  ],
};

fs.mkdirSync(demoDir, { recursive: true });
fs.writeFileSync(path.join(demoDir, 'test-issuer.json'), JSON.stringify(issuer, null, 2) + '\n');
// Numeric mode, as UIDAI's codes; low error correction keeps 3,000+ digits readable.
await QRCode.toFile(path.join(demoDir, 'synthetic-qr.png'), [{ data: text, mode: 'numeric' }], { errorCorrectionLevel: 'L', margin: 4, scale: 4 });
console.log(`demo ready: ${path.relative(process.cwd(), path.join(demoDir, 'synthetic-qr.png'))} (synthetic QR, ${text.length} digits), test issuer key written`);

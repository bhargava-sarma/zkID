#!/usr/bin/env node
// Prepares the local demo: two ephemeral TEST issuer keys, one for Aadhaar QRs
// and one for PAN records, a SYNTHETIC Secure QR (V5 layout, fake values) signed
// with the first, as a PNG, and a SYNTHETIC PAN Verification Record (DigiLocker's
// XML, fake values, verified now) signed with the second, to use in the holder
// app. The private keys exist only while this script runs. Writes, gitignored:
//   apps/demo-rp/.demo/test-issuer.json    public keys, for the demo verifiers and
//                                          a demo build of the holder app
//   apps/demo-rp/.demo/synthetic-qr.png    the QR image
//   apps/demo-rp/.demo/synthetic-pan.xml   the PAN record (shops accept it for 7 days)
// Usage: node setup-demo.mjs

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import QRCode from 'qrcode';
import { keyHash } from '../../packages/circuit/index.mjs';
import { panKeyHash } from '../../packages/pan/keyhash.mjs';
import { makeRecord, testIssuer as panTestIssuer } from '../../packages/pan/synthetic.mjs';
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
const pan = panTestIssuer();
const panXml = await makeRecord(pan);
const modulusOf = (key) => Buffer.from(key.export({ format: 'jwk' }).n, 'base64url').toString('hex');
const issuer = {
  note: 'TEST issuers for the local demo: ephemeral keys, NOT UIDAI and NOT DigiLocker. Never trust them outside the demo.',
  keys: [
    {
      id: 'demo-test-key',
      label: 'TEST ISSUER (local demo, not UIDAI)',
      document: 'aadhaar',
      modulus: modulusOf(publicKey),
      keyHash: keyHash(publicKey),
      notBefore: 0,
      notAfter: 2 ** 32,
    },
    {
      id: 'demo-test-pan-key',
      label: 'TEST ISSUER (local demo, not DigiLocker)',
      document: 'pan',
      modulus: modulusOf(pan.publicKey),
      keyHash: panKeyHash(modulusOf(pan.publicKey)),
      notBefore: 0,
      notAfter: 2 ** 32,
    },
  ],
};

fs.mkdirSync(demoDir, { recursive: true });
fs.writeFileSync(path.join(demoDir, 'test-issuer.json'), JSON.stringify(issuer, null, 2) + '\n');
// Numeric mode, as UIDAI's codes; low error correction keeps 3,000+ digits readable.
await QRCode.toFile(path.join(demoDir, 'synthetic-qr.png'), [{ data: text, mode: 'numeric' }], { errorCorrectionLevel: 'L', margin: 4, scale: 4 });
fs.writeFileSync(path.join(demoDir, 'synthetic-pan.xml'), panXml);
const shown = (file) => path.relative(process.cwd(), path.join(demoDir, file));
console.log(`demo ready: ${shown('synthetic-qr.png')} (synthetic QR, ${text.length} digits), ${shown('synthetic-pan.xml')} (synthetic PAN record), test issuer keys written`);

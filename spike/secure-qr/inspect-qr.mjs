#!/usr/bin/env node
// Describes the structure of a Secure QR of any version without printing any
// value: signature check, then each 0xFF-separated field's length and kind,
// then where the photo starts and its format. For layouts the parser does not
// know yet (e.g. V5). The output is safe to share.
//
// Usage: node inspect-qr.mjs local/a.txt [--cert <file>...]

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeEnvelope, findSigner, parseReferenceId } from './secure-qr.mjs';
import { loadUidaiCerts } from './certs.mjs';

const IMAGES = [
  { type: 'JPEG 2000 codestream', start: [0xff, 0x4f, 0xff, 0x51], end: [0xff, 0xd9] },
  { type: 'JPEG 2000 (JP2 file)', start: [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20], end: [0xff, 0xd9] },
  { type: 'JPEG', start: [0xff, 0xd8, 0xff], end: [0xff, 0xd9] },
  { type: 'PNG', start: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], end: [0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82] },
];

const startsWith = (buf, at, bytes) => bytes.every((b, i) => buf[at + i] === b);
const imageAt = (buf, at) => IMAGES.find((img) => startsWith(buf, at, img.start)) ?? null;

// A description of a field that never contains its characters.
export function kind(buf) {
  if (buf.length === 0) return 'empty';
  const s = buf.toString('latin1');
  if (/^V[0-9]+$/.test(s)) return 'version marker';
  if (/^[0-9]+$/.test(s)) return buf.length === 1 ? '1 digit' : `${buf.length} digits`;
  if (/^[0-9]{2}-[0-9]{2}-[0-9]{4}$/.test(s)) return 'date pattern DD-MM-YYYY';
  if (/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(s)) return 'date pattern YYYY-MM-DD';
  if (/^[0-9]{2}\/[0-9]{2}\/[0-9]{4}$/.test(s)) return 'date pattern DD/MM/YYYY';
  if (buf.every((b) => b >= 0x20 && b < 0x7f)) {
    if (/^[A-Za-z]$/.test(s)) return 'one letter';
    if (/^[A-Za-z .,'\-]+$/.test(s)) return `${buf.length} bytes, letters and spaces`;
    // Short mixed fields get a shape (a = letter, 9 = digit), never the characters.
    const shape = buf.length <= 12 ? `, shape ${s.replace(/[A-Za-z]/g, 'a').replace(/[0-9]/g, '9')}` : '';
    return `${buf.length} bytes, printable ASCII with digits or symbols${shape}`;
  }
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buf);
    return `${buf.length} bytes, UTF-8 text with non-ASCII characters`;
  } catch {
    return `${buf.length} bytes, binary`;
  }
}

// Fields up to the first one that starts with an image signature.
export function scanFields(signedData) {
  const fields = [];
  let pos = 0;
  while (pos < signedData.length && fields.length < 64) {
    const image = imageAt(signedData, pos);
    if (image) {
      const endAt = signedData.lastIndexOf(Buffer.from(image.end));
      const end = endAt >= pos ? endAt + image.end.length : null;
      return { fields, image: { type: image.type, offset: pos, length: end && end - pos, end, after: end && signedData.length - end } };
    }
    const delimiter = signedData.indexOf(0xff, pos);
    if (delimiter === -1) break;
    fields.push({ offset: pos, bytes: signedData.subarray(pos, delimiter) });
    pos = delimiter + 1;
  }
  return { fields, image: null };
}

function main() {
  const args = process.argv.slice(2);
  const file = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--cert');
  if (!file) {
    console.error('Usage: node inspect-qr.mjs <qr-text-file> [--cert <file>...]');
    process.exit(2);
  }
  const extra = args
    .flatMap((a, i) => (a === '--cert' ? [args[i + 1]] : []))
    .map((p) => ({ label: p, cert: new crypto.X509Certificate(fs.readFileSync(p)) }));

  const qr = decodeEnvelope(fs.readFileSync(file, 'utf8'));
  console.log(`envelope    ${qr.compression}, ${qr.compressedLength} compressed bytes, ${qr.dataLength} decompressed`);
  console.log(`            ${qr.signedData.length} signed bytes + ${qr.signature.length}-byte signature`);
  const signer = findSigner(qr, [...loadUidaiCerts(), ...extra]);
  console.log(`signature   ${signer ? `VALID under ${signer.label}` : 'NOT verified by any certificate given'}`);

  const { fields, image } = scanFields(qr.signedData);
  console.log(`fields      ${fields.length} before the photo`);
  fields.forEach(({ offset, bytes }, i) => {
    let note = kind(bytes);
    if (bytes.length === 21 && /^[0-9]+$/.test(bytes.toString('latin1'))) {
      try {
        note += `, reads as a reference ID generated ${parseReferenceId(bytes).generatedAt.toISOString().slice(0, 10)}`;
      } catch {
        note += ', not a valid reference-ID timestamp';
      }
    }
    console.log(`  #${String(i).padEnd(3)} at ${String(offset).padStart(4)}  ${note}`);
  });
  if (image) {
    console.log(`photo       ${image.type} at offset ${image.offset}, right after field #${fields.length - 1}`);
    console.log(`            ${image.length ?? 'unknown'} bytes; ${image.after ?? 'unknown'} bytes after its end marker`);
    if (image.after) {
      const parts = [];
      const rest = qr.signedData.subarray(image.end);
      for (let pos = 0; pos <= rest.length; ) {
        const next = rest.indexOf(0xff, pos);
        const stop = next === -1 ? rest.length : next;
        parts.push(kind(rest.subarray(pos, stop)));
        pos = stop + 1;
      }
      const delimiters = parts.length - 1;
      console.log(`after photo ${delimiters ? `${delimiters} 0xFF delimiter(s)` : 'no 0xFF delimiter'}; parts: ${parts.join(' | ')}`);
    }
  } else {
    console.log('photo       no known image signature at the start of any field');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

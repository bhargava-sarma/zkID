// SYNTHETIC PAN Verification Records for tests: DigiLocker's layout, XML
// serialization and signature scheme, with fake values, signed by an ephemeral
// TEST key under a self-signed TEST certificate. The key lives in memory only.
// Nothing here is real: the name is "SYNTHETIC TEST PERSON" and the QR says so.

import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { DOMParser } from '@xmldom/xmldom';
import { ExclusiveCanonicalization } from 'xml-crypto';
import QRCode from 'qrcode';
import { signedInfoFor } from './format.mjs';

// ---- A self-signed TEST certificate, in DER -----------------------------------

function der(tag, ...parts) {
  const body = Buffer.concat(parts);
  const len = body.length < 128 ? Buffer.from([body.length]) : (() => {
    const bytes = [];
    for (let n = body.length; n > 0; n >>= 8) bytes.unshift(n & 0xff);
    return Buffer.from([0x80 | bytes.length, ...bytes]);
  })();
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
const seq = (...parts) => der(0x30, ...parts);
const oid = (dotted) => {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const bytes = [40 * a + b];
  for (const n of rest) {
    const chunk = [n & 0x7f];
    for (let v = n >> 7; v > 0; v >>= 7) chunk.unshift(0x80 | (v & 0x7f));
    bytes.push(...chunk);
  }
  return der(0x06, Buffer.from(bytes));
};
const name = (cn) => seq(der(0x31, seq(oid('2.5.4.3'), der(0x0c, Buffer.from(cn, 'utf8')))));
const utcTime = (date) => der(0x17, Buffer.from(`${date.toISOString().slice(2, 19).replace(/[-:T]/g, '')}Z`));
const SHA256_WITH_RSA = seq(oid('1.2.840.113549.1.1.11'), der(0x05));

export const TEST_SUBJECT = 'TEST ISSUER (zkID PAN spike, not DigiLocker)';

// A TEST signing key and its self-signed certificate.
export function testIssuer() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const now = new Date();
  const tbs = seq(
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, crypto.randomBytes(8).fill(0x01, 0, 1)),
    SHA256_WITH_RSA,
    name(TEST_SUBJECT),
    seq(utcTime(new Date(now.getTime() - 86400e3)), utcTime(new Date(now.getTime() + 365 * 86400e3))),
    name(TEST_SUBJECT),
    publicKey.export({ type: 'spki', format: 'der' }),
  );
  const signature = crypto.sign('sha256', tbs, privateKey);
  const certificate = seq(tbs, SHA256_WITH_RSA, der(0x03, Buffer.from([0]), signature));
  return { privateKey, publicKey, certificate };
}

// ---- The record -----------------------------------------------------------------

const ddmmyyyy = (date) => `${String(date.getUTCDate()).padStart(2, '0')}-${String(date.getUTCMonth() + 1).padStart(2, '0')}-${date.getUTCFullYear()}`;
// DigiLocker writes verifiedOn in IST.
export const istStamp = (date) => {
  const ist = new Date(date.getTime() + 5.5 * 3600e3);
  return `${ddmmyyyy(ist)} ${ist.toISOString().slice(11, 19)}`;
};

// A PNG chunk: length, type, data, CRC-32.
function chunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length);
  head.write(type, 4, 'latin1');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(zlib.crc32(Buffer.concat([head.subarray(4), data])));
  return Buffer.concat([head, data, crc]);
}

// The QR DigiLocker embeds: a 1-bit palette PNG of a version 20 QR, 2 pixels a
// module, 4 modules of margin (210 x 210, about 1.7 KB). Here, of synthetic text
// of the same length.
function syntheticQr(fields) {
  const content = `SYNTHETIC TEST RECORD - NOT A REAL PAN|${fields.name}|${fields.pan}|${fields.dob}|`.padEnd(632, '0');
  const { modules } = QRCode.create(content, { version: 20, errorCorrectionLevel: 'L' });
  const scale = 2;
  const margin = 4;
  const size = (modules.size + 2 * margin) * scale;
  const rowBytes = Math.ceil(size / 8);
  const raw = Buffer.alloc((rowBytes + 1) * size); // filter byte 0, then the row
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const [mx, my] = [Math.floor(x / scale) - margin, Math.floor(y / scale) - margin];
      const dark = mx >= 0 && my >= 0 && mx < modules.size && my < modules.size && modules.get(my, mx);
      if (dark) raw[y * (rowBytes + 1) + 1 + (x >> 3)] |= 0x80 >> (x & 7);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.set([1, 3, 0, 0, 0], 8); // 1 bit, palette
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('PLTE', Buffer.from([255, 255, 255, 0, 0, 0])),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
  return png.toString('base64');
}

// A signed record, serialized as DigiLocker serializes one. `edit` changes the
// unsigned XML text before signing, to make records the circuit must refuse.
export async function makeRecord(issuer, options = {}) {
  const fields = {
    pan: 'TESTP0000T',
    name: 'SYNTHETIC TEST PERSON',
    dob: '01-01-1990',
    gender: 'MALE',
    uid: crypto.randomBytes(16).toString('hex'),
    verifiedOn: istStamp(new Date()),
    status: 'A',
    ...options,
  };
  const qr = fields.qr ?? syntheticQr(fields);
  let body =
    `<Certificate language="99" name="PAN Verification Record" type="PANCR" number="${fields.pan}" issuedAt="DigiLocker" issueDate="" validFromDate="" status="${fields.status}">` +
    '<IssuedBy><Organization name="Income Tax Department" code="" tin="" uid="" type="CG"><Address type="" line1="" line2="" house="" landmark="" locality="" vtc="" district="" pin="" state="" country="IN"/></Organization></IssuedBy>' +
    `<IssuedTo><Person uid="${fields.uid}" title="" name="${fields.name}" dob="${fields.dob}" swd="" swdIndicator="" gender="${fields.gender}" maritalStatus="" religion="" phone="" email="">` +
    '<Address type="permanent" line1="" line2="" house="" landmark="" locality="" vtc="" district="" pin="" state="" country="IN"/><Photo format=""/></Person></IssuedTo>' +
    `<CertificateData><PAN num="${fields.pan}" verifiedOn="${fields.verifiedOn}"/></CertificateData><QRMeta>${qr}</QRMeta>`;
  if (options.edit) body = options.edit(body);

  const unsigned = new DOMParser().parseFromString(`${body}</Certificate>`, 'text/xml');
  const canonical = new ExclusiveCanonicalization().process(unsigned.documentElement, {}).toString();
  const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest('base64');
  const signatureValue = crypto.sign('sha1', Buffer.from(signedInfoFor(digest), 'utf8'), issuer.privateKey).toString('base64');
  return (
    `<?xml version="1.0" encoding="utf-8"?>\n${body}<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">\n` +
    '  <SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n' +
    '    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>\n' +
    '  <Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms>' +
    `<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>${digest}</DigestValue></Reference></SignedInfo><SignatureValue>${signatureValue}</SignatureValue>\n` +
    `<KeyInfo><X509Data><X509SubjectName>CN=${TEST_SUBJECT}</X509SubjectName><X509Certificate>${issuer.certificate.toString('base64')}</X509Certificate></X509Data></KeyInfo></Signature></Certificate>\n`
  );
}

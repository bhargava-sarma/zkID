# @zkid/secure-qr

Parse and verify Aadhaar Secure QR codes, in Node and in the browser. Started
as the Phase 1 spike; the findings are in
[docs/issuer-research.md](../../docs/issuer-research.md).

```bash
cd packages/secure-qr
npm install
npm run fetch-uidai-sample   # UIDAI's official V1 sample -> local/ (gitignored)
npm test                     # synthetic V2 and V5 codes, negative controls, browser decoder, UIDAI sample
node verify-qr.mjs local/uidai-official-sample-v1.txt
node read-qr-image.mjs local/qr-a.png local/a.txt    # a QR screenshot -> its text
node inspect-qr.mjs local/a.txt                      # structure of any version, no values
node compare-downloads.mjs local/a.txt local/b.txt   # Phase 1.3, on two real downloads
```

The parser has no dependencies (`node:zlib`, `node:crypto`).
`read-qr-image.mjs` reads PNG or JPEG images with jsqr, pngjs and jpeg-js. It
runs locally and never prints what the code contains.

- `secure-qr.mjs` decodes, parses and verifies a code in Node. Every failure
  throws an error with a code.
- `web.mjs` does the same in a browser (`DecompressionStream`, WebCrypto), with
  the same error codes. The holder app uses it to check a QR's signature before
  proving (THREAT_MODEL tests T7.3, T7.5).
- `layout.mjs` is the byte layout both share: fields, photo, signature. It uses
  no platform API.
- `synthetic.mjs` builds **synthetic** V2 or V5 codes signed with a caller's test key.
  All values are labelled fake, and the tests check that they never verify
  under a UIDAI certificate.
- `certs/` holds UIDAI's public Secure QR certificates.
  [`registry.json`](certs/registry.json) records their provenance,
  validity and fingerprints.
- `verify-qr.mjs` and `compare-downloads.mjs` print structure and equality
  only, never names, dates of birth, addresses, ID digits or photo bytes.

Real codes go in `local/`, which is gitignored. Never commit one. Clones from
before this package moved out of `spike/` keep their files in
`spike/secure-qr/local/`, which also stays gitignored.

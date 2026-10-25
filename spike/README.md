# Phase 1 spikes

Throwaway-quality code that answers the Phase 1 feasibility questions. The
findings are in [docs/issuer-research.md](../docs/issuer-research.md).

## secure-qr: parse and verify Aadhaar Secure QR codes in plain Node

```bash
cd spike/secure-qr
npm install
npm run fetch-uidai-sample   # UIDAI's official V1 sample -> local/ (gitignored)
npm test                     # synthetic V2 codes, negative controls, UIDAI sample
node verify-qr.mjs local/uidai-official-sample-v1.txt
node read-qr-image.mjs local/qr-a.png local/a.txt    # a QR screenshot -> its text
node inspect-qr.mjs local/a.txt                      # structure of any version, no values
node compare-downloads.mjs local/a.txt local/b.txt   # Phase 1.3, on two real downloads
```

The parser has no dependencies (`node:zlib`, `node:crypto`).
`read-qr-image.mjs` reads PNG or JPEG images with jsqr, pngjs and jpeg-js. It
runs locally and never prints what the code contains.

- `secure-qr.mjs` decodes, parses and verifies a code. Every failure throws an
  error with a code.
- `synthetic.mjs` builds **synthetic** V2 codes signed with a caller's test key.
  All values are labelled fake, and the tests check that they never verify
  under a UIDAI certificate.
- `certs/` holds UIDAI's public Secure QR certificates.
  [`registry.json`](secure-qr/certs/registry.json) records their provenance,
  validity and fingerprints.
- `verify-qr.mjs` and `compare-downloads.mjs` print structure and equality
  only, never names, dates of birth, addresses, ID digits or photo bytes.

Real codes go in `spike/secure-qr/local/`, which is gitignored. Never commit one.

## circuit-cost: constraint counts and proving cost

```bash
cd spike/circuit-cost
npm install
bash measure_constraints.sh              # needs circom on PATH and the Anon Aadhaar clone
AA_ARTIFACTS=<dir> node bench_prove_node.mjs
AA_ARTIFACTS=<dir> PLAYWRIGHT=<path> node bench_prove_browser.mjs
```

`<dir>` holds Anon Aadhaar's published v2.0.0 `aadhaar-verifier.wasm`,
`circuit_final.zkey` and `vkey.json`, from
`https://anon-aadhaar-artifacts.s3.eu-central-1.amazonaws.com/v2.0.0/`. The
proving benchmarks use synthetic V2 codes under ephemeral keys. The circuit
takes the RSA key as an input, so no real data is needed. Results are written
to `results/`.

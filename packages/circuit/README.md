# @zkid/circuit

Anon Aadhaar's Secure QR circuit, `AadhaarQRVerifier(121, 17, 1536)`, from its
published v2.0.0 artifacts. zkID uses it **unchanged** (option A); it is prior
work by PSE, MIT-licensed. What it checks, what it does not, and the measured
cost are in [docs/circuit-spec.md](../../docs/circuit-spec.md).

```bash
cd packages/circuit
npm install
npm run fetch      # artifacts/ (623 MB), each file checked against artifacts.json
npm test           # controls T1.2-T1.4, T1.7-T1.10, T4.1, T5.1, T7.1, T7.6 (about 5 minutes)
npm run bench:node
bash setup/verify-setup.sh   # rebuilds the circuit and runs snarkjs zkey verify (about 15 minutes)
```

`AA_ARTIFACTS=<dir>` points the tests and benchmarks at artifacts kept
elsewhere. Without artifacts, the circuit tests are reported as skipped.

## API (`index.mjs`)

- `buildInput(qrText, key, { nullifierSeed, signalHash })`: the circuit input
  for a V2 or V5 Secure QR and the RSA key (or certificate) that signed it. Only
  the age bit is revealed. Fails with a typed error (`UNSUPPORTED_LAYOUT`,
  `DATA_TOO_LONG`, `PHOTO_TOO_LARGE`, `BAD_PUBLIC_INPUT`, `UNSUPPORTED_KEY`)
  where the circuit cannot read the code; it does not check the signature, the
  circuit does.
- `keyHash(key)`: the circuit's `pubkeyHash` for a key, for the issuer registry.
- `witness(input)`, `prove(input)`, `verify(proof, publicSignals)`: witness
  outputs, a Groth16 proof, and its verification. Every artifact is checked
  against `artifacts.json` first (`ARTIFACT_MISSING`, `ARTIFACT_MISMATCH`). A
  failed constraint is `WITNESS_FAILED` with the template's name.
- `PUBLIC_SIGNALS`, `namedSignals(publicSignals)`: the nine public signals by
  name.
- `close()`: stops snarkjs's worker threads.

## Benchmarks

- `bench/node.mjs`: witness and proof time in Node.
- `bench/browser.mjs`: runs the phone benchmark page
  (`frontend/public/bench/`) in headless Chromium.
- `bench/make-phone-bench.mjs`: writes the page's synthetic input.

Results go to `bench/results/`.

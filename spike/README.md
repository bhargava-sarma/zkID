# Spikes

Throwaway-quality code that answers feasibility questions. The Phase 1
findings are in [docs/issuer-research.md](../docs/issuer-research.md).

## pan: DigiLocker PAN records

A prototype circuit for DigiLocker's PAN Verification Record, with tests and
timings: [pan/README.md](pan/README.md).

## secure-qr

The Secure QR parser began here and is now
[`packages/secure-qr`](../packages/secure-qr/README.md), used by the circuit
package. Its Phase 1 results are unchanged.

## circuit-cost: constraint counts and proving cost

```bash
cd spike/circuit-cost
npm install
bash measure_constraints.sh              # needs circom on PATH and the Anon Aadhaar clone
AA_ARTIFACTS=<dir> node bench_prove_node.mjs
AA_ARTIFACTS=<dir> PLAYWRIGHT=<path> node bench_prove_browser.mjs
```

`results/prove_node_v1.json` measured v1's circuit with a script that needed
the v1 tree; it was removed with v1's code (last at commit `666c4a2`).
`measure_constraints.sh` reads v1's circuit from tag `v1-mock-issuer-demo`.

`<dir>` holds Anon Aadhaar's published v2.0.0 `aadhaar-verifier.wasm`,
`circuit_final.zkey` and `vkey.json`, from
`https://anon-aadhaar-artifacts.s3.eu-central-1.amazonaws.com/v2.0.0/`. The
proving benchmarks use synthetic V2 codes under ephemeral keys. The circuit
takes the RSA key as an input, so no real data is needed. Results are written
to `results/`.

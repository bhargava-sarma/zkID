# Attack suite

Every attack in [docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md) is checked by a
test, and [docs/ATTACK_REPORT.md](../docs/ATTACK_REPORT.md) is generated from a
run of them all: each attack, whether zkID defends it, and the tests that
passed.

- The defended attacks are tested where the defence lives: `packages/circuit`
  (forged or altered QRs), `packages/verifier-sdk` (replay, freshness,
  nullifiers, tampering), `packages/secure-qr`, `packages/issuer-registry`,
  the holder app (`frontend/src/holder`) and the end-to-end test
  (`apps/demo-rp`).
- [`test/not-defended.test.ts`](test/not-defended.test.ts) shows the attacks
  zkID does **not** defend working, with real proofs: a relayed request
  (T2.6), a lent QR (T3.1), a photo update (T3.4), other formats (T4.2), an
  address update (T4.3), nullifiers computed from a copy of the QR (T5.2), and
  matching by generation hour and key (T5.3).

A test cites the threat model by starting its name with the test id, as in
`T2.1: …`. `report.mjs` reads those ids.

## Run

Install every suite, fetch the circuit artifacts, and install Chromium for the
end-to-end test:

```bash
for d in packages/secure-qr packages/circuit packages/issuer-registry packages/verifier-sdk frontend apps/demo-rp attack-suite; do (cd $d && npm install); done
(cd packages/circuit && npm run fetch)
(cd apps/demo-rp && npx playwright install chromium)
```

Then, from the repository root:

```bash
(cd attack-suite && npm test)   # only the not-defended attacks (about 4 minutes)
node attack-suite/report.mjs    # every suite, then docs/ATTACK_REPORT.md (about 20 minutes)
```

`report.mjs` writes the report only if every test passes, no cited test is
skipped, and every test the threat model cites ran. Otherwise it lists the
problems and exits 1. CI runs it and fails if the committed report differs
from the one it generated.

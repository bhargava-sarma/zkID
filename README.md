# zkID

> **Status: v2 in progress on this branch.** v1 (an OCR-based demo with its own
> "issuer") is preserved at tag `v1-mock-issuer-demo`, and its server code is
> removed here. v1's only trusted issuer key is public, so its Sepolia
> contracts and the live v1 site accept forged proofs; see
> [SECURITY_NOTES.md](SECURITY_NOTES.md).

zkID lets a website check that a person is 19 or older from their Aadhaar Secure
QR (the QR on e-Aadhaar, signed by UIDAI) without receiving the QR or anything
in it. The person's browser checks UIDAI's signature and makes a zero-knowledge
proof; the website receives only the proof.

The circuit and its proving key are Anon Aadhaar's (by PSE, MIT-licensed),
used unchanged ([docs/circuit-spec.md](docs/circuit-spec.md)). zkID adds a
request protocol that binds each proof to one website and one expiring request,
a per-website nullifier, a registry of UIDAI keys with their validity windows, a
verifier SDK with typed failure codes, a holder app that proves in the browser,
and a demo website.

## What a website learns

- That UIDAI signed a QR showing the holder was 19 or older on the day the QR
  was generated. The circuit's `ageAbove18` output means "completed age above
  18", which becomes true on the 19th birthday; 18-year-olds cannot prove.
- The hour the QR was generated, and which UIDAI key signed it.
- A nullifier: the same for the same QR at the same website (one account per
  QR per site), different at every other website.

It does not learn the name, date of birth, gender, address, Aadhaar number or
photo. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) lists every attack
considered, which are defended and which are not, and the test for each;
[docs/ATTACK_REPORT.md](docs/ATTACK_REPORT.md) is generated from a run of those
tests.

## Limits

- **Anyone with a copy of the QR can prove as its holder.** Nothing binds a
  proof to the person; preventing lending needs biometrics (THREAT_MODEL
  A3.1, A3.3).
- **Freshness is the only revocation.** A website chooses how old a QR it
  accepts (the demo: 7 days).
- **Memory.** Proving in a desktop browser takes about 45 s and 5 GB, or about
  80 s and 2.6 GB on one thread. On the one phone tried, the tab ran out of
  memory ([docs/circuit-spec.md](docs/circuit-spec.md), section 5).
- **Not every holder can prove:** photos above 924–987 bytes do not fit the
  circuit, and the date of birth must be `DD-MM-YYYY`.
- **The nullifier comes from the photo, the bytes after it, and the length of
  the signed data.** Two downloads of one e-Aadhaar, a day apart, matched in
  all three. A new photo, or an update that changes a field's length (a new
  address, say), gives a new nullifier, so a second account at the same site.
- **Research prototype.** Whether a website needs UIDAI's permission to use
  Secure QR this way is unsettled ([docs/issuer-research.md](docs/issuer-research.md),
  section 8).

## How it works

1. The website creates a request (`createRequest` in the verifier SDK): its
   HTTPS origin as verifier id, a random challenge, the maximum QR age and an
   expiry. It sends the person to the holder app with the request's URL.
2. The holder app fetches the request from that origin, and refuses one that
   names another origin or asks for more than the age bit.
3. The person picks an image of their Secure QR. The app reads it, checks
   UIDAI's signature against the registry's keys, and checks freshness and age
   locally, so a proof that would be refused is not made.
4. A Web Worker downloads the circuit files once (about 300 MB, each checked
   by SHA-256, then cached) and proves. The nullifier seed and the signal hash
   are hashes of the verifier id and of the whole request.
5. The app posts `{ proof, publicSignals }` to the website, whose `verify`
   checks the request, the nullifier seed, the challenge, the proof, the
   issuer key and its validity window, the age bit, freshness and the
   nullifier, and returns the first failure as a code.

## Layout

```
packages/secure-qr/        Secure QR parser and signature check, Node and browser; synthetic test codes
packages/circuit/          Anon Aadhaar's circuit artifacts, pinned by SHA-256; circuit input; tests, benchmarks
packages/issuer-registry/  UIDAI's keys with validity windows; refuses test and compromised keys in production
packages/verifier-sdk/     createRequest and verify, with typed failure codes (TypeScript)
frontend/                  The holder app (src/App.jsx, src/holder/), and the phone benchmark page (public/bench/)
apps/demo-rp/              Demo website: request, request QR, verify, one account per nullifier; end-to-end test
attack-suite/              Tests of the attacks zkID does not defend; generates docs/ATTACK_REPORT.md
docs/                      Issuer research, threat model, attack report, circuit specification
backend/                   A health endpoint, plus the v1 circuits and contracts (all retired)
tools/                     Test issuer (TEST keys only), v1 audit scripts, repository checks
spike/                     Phase 1 measurements
security/                  Keys whose private half is public; never trust them
```

`frontend/src/contracts/` holds v1's contract addresses (all retired) and
client; nothing imports it.

## Run the demo

See [apps/demo-rp/README.md](apps/demo-rp/README.md): a local holder app, two
demo websites, and a synthetic QR signed by a TEST key generated on your
machine. Real QRs are never needed, and must never be committed.

## Tests and the attack suite

```bash
(cd packages/secure-qr && npm test)         # parser, signature, synthetic codes, browser decoder
(cd packages/circuit && npm test)           # the circuit's controls on synthetic QRs (about 5 min; npm run fetch first)
(cd packages/issuer-registry && npm test)   # registry checks
(cd packages/verifier-sdk && npm test)      # every failure code, with real proofs
(cd frontend && npm test)                   # holder app: request and QR checks, circuit input
(cd apps/demo-rp && npm run test:e2e)       # three proofs in headless Chromium, network capture
(cd attack-suite && npm test)               # the attacks zkID does not defend, shown working
node attack-suite/report.mjs                # all of the above that the threat model cites -> docs/ATTACK_REPORT.md
node --test "tools/repo-checks/*.test.mjs"  # no private key tracked; threat model consistent
(cd backend/hardhat-deploy && npm test)     # v1 ZkIdPolicy, kept until the chain decision
```

Run `npm install` in a package first. Several packages import
`packages/circuit`, so install it too. The end-to-end test needs Chromium
(`cd apps/demo-rp && npx playwright install chromium`). CI
([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs all of it, and fails
if the committed attack report differs from the one its run generates.
[attack-suite/README.md](attack-suite/README.md) has the details.

## v1 on Ethereum Sepolia (RETIRED)

**Do not use.** `ZkIdPolicy` trusts the v1 demo issuer key, whose private key is
public, and returns `Accepted` for forged proofs; this was checked read-only on
2026-10-20 ([SECURITY_NOTES.md](SECURITY_NOTES.md), [`tools/v1-audit`](tools/v1-audit)).
The verifiers accept proofs under any issuer key.

| Contract | Role | Address |
|---|---|---|
| `ZkIdPolicy` | Relying-party policy over both verifiers (retired) | [`0x8eDa6b1A54900c60C6b730796FfDd51a5327714f`](https://sepolia.etherscan.io/address/0x8eDa6b1A54900c60C6b730796FfDd51a5327714f) |
| `CredentialAgeVerifier` | Age proof, 18 public signals (retired) | [`0x1052Fc75ce491137D4FA7691b427D5356505b1cd`](https://sepolia.etherscan.io/address/0x1052Fc75ce491137D4FA7691b427D5356505b1cd) |
| `CredentialMatchVerifier` | Name and gender proof, 19 public signals (retired) | [`0x7bD0f448459f1Eb3F80113df712F2f71DD0B7641`](https://sepolia.etherscan.io/address/0x7bD0f448459f1Eb3F80113df712F2f71DD0B7641) |

They and three older verifiers are listed under `retired` in
[`frontend/src/contracts/addresses.json`](frontend/src/contracts/addresses.json).
`npm run deploy:policy` refuses to run. Only the policy's owner can make it stop
accepting the public key (`setIssuer(<demo modulus limbs>, false)`); nothing in
this repository sends that transaction.

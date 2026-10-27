# zkID

Prove to a website that your Aadhaar Secure QR meets its rules, such as "19 or
older", without the website receiving the QR. A website can also set rules on
gender, PIN code and state; those reveal the holder's value of the field.

> **Status: research prototype.** v1 (an OCR-based demo with its own "issuer")
> is preserved at tag `v1-mock-issuer-demo`. v1's only trusted issuer key is
> public, so its Sepolia contracts and the live v1 site accept forged proofs;
> see [SECURITY_NOTES.md](SECURITY_NOTES.md).

The Secure QR on every e-Aadhaar is signed by UIDAI. zkID's holder app reads it
on the person's device, checks UIDAI's signature, and makes a zero-knowledge
proof in the browser; the website receives only the proof. The circuit and its
proving key are Anon Aadhaar's, used unchanged
([docs/circuit-spec.md](docs/circuit-spec.md)). zkID adds a request protocol
that binds each proof to one website and one expiring request, per-website
nullifiers, a registry of UIDAI keys with their validity windows, a verifier SDK
with typed failure codes, the holder app, a demo website, and an attack suite.

## How it works

1. The website creates a request (`createRequest` in the verifier SDK): its
   HTTPS origin as verifier id, a random challenge, the maximum QR age, an
   expiry and its rules (19 or older; accepted genders, PIN codes and states).
   It sends the person to the holder app with the request's URL.
2. The holder app fetches the request from that origin, and refuses one that
   names another origin or is malformed.
3. The person picks an image of their Secure QR. The app reads it, checks
   UIDAI's signature against the registry's keys, and checks freshness and the
   rules locally, so a proof that would be refused is not made. It shows the
   person exactly what the website will learn.
4. A Web Worker downloads the circuit files once (about 300 MB, each checked
   by SHA-256, then cached) and proves. The nullifier seed and the signal hash
   are hashes of the verifier id and of the whole request.
5. The app posts `{ proof, publicSignals }` to the website, whose `verify`
   checks the request, the nullifier seed, the challenge, the proof, the
   issuer key and its validity window, the rules, freshness and the
   nullifier, and returns the first failure as a code.

## What a website learns

- That UIDAI signed a QR meeting its rules. With "19 or older", only that: the
  circuit's `ageAbove18` output means "completed age above 18", which becomes
  true on the 19th birthday; 18-year-olds cannot prove.
- With a rule on gender, PIN code or state, the holder's value of that field,
  not only that it passes: the circuit outputs the value. A shop accepting 50
  PIN codes learns which one. The holder app shows these values before proving,
  and reveals nothing when the QR breaks a rule
  ([docs/DECISIONS.md](docs/DECISIONS.md), section 10).
- The hour the QR was generated, and which UIDAI key signed it.
- A nullifier: the same for the same QR at the same website (one account per
  QR per site), different at every other website.

It does not learn the name, date of birth, Aadhaar number, photo or the rest of
the address, nor gender, PIN code or state unless it has a rule on them.

## What is defended, and what is not

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) lists 41 attacks: 26 defended, 3
partly, 12 not. [docs/ATTACK_REPORT.md](docs/ATTACK_REPORT.md) is generated from
a run of the tests for each, including the ones that show the undefended attacks
working. The ids below are the threat model's.

Defended:

- **Forgery** (A1.1–A1.5, A1.7–A1.9, A1.11): a QR UIDAI did not sign, one
  changed in any signed byte, one showing someone under 19, or one that breaks
  a website's gender, PIN code or state rule gives no accepted proof. A key
  outside the registry, or a QR generated outside its key's validity window, is
  refused; the circuit files are pinned by SHA-256.
- **Replay** (A2.1–A2.4): a proof is accepted once, by the website and for the
  request it was made for, before the request expires. A re-randomized copy is
  caught too.
- **A second account with the same QR** at one website (A3.2, A4.1, A4.2),
  including with a re-downloaded QR, as tested on one holder's two downloads.
- **Linking by nullifier** across websites, by anyone who has not seen the QR
  (A5.1, A5.5).
- **A website asking for more** than its rules: the date of birth, or the QR
  itself (A6.2, A6.4).
- **Tampering** with the proof, its signals, the request or the QR text (A7).

Not defended:

- **Lending and copies** (A3.1, A3.3): anyone with a copy of the QR proves as
  its holder, and the first to prove at a site takes that site's account.
  Preventing this needs biometrics.
- **New accounts after an update** (A3.4, A4.4, A4.6): a new photo, or an
  update that changes a field's length (a new address, say), gives a new
  nullifier, so a second account at every site.
- **Linking by anyone who has the QR** (A5.2), and by the generation hour and
  key hash that every proof shows (A5.3, A6.3).
- **A relayed request** (A2.5): whoever forwards a website's live request to
  you gets the account your proof opens.
- **UIDAI itself** (A1.6, A4.5): its signing key and its de-duplication are
  trusted. **Network correlation** (A5.4) is out of scope.
- **Partly:** a date of birth with unusual characters relies on UIDAI's
  formatting (A1.10), QRs from other sources may carry different bytes, so a
  different nullifier (A4.3), and a website that writes a rule on gender, PIN
  code or state to admit everyone learns the value of everyone who goes on
  (A6.1).

## Limits

- **19, not 18.** Anon Aadhaar's circuit outputs "completed age above 18"; the
  owner accepted this rather than change the circuit
  ([docs/DECISIONS.md](docs/DECISIONS.md), section 2). No other age can be
  asked for.
- **Rules reveal values.** A rule on gender, PIN code or state shows the website
  the value; proving only that it passes would need a new circuit
  ([docs/DECISIONS.md](docs/DECISIONS.md), section 10).
- **Freshness is the only revocation.** A website chooses how old a QR it
  accepts (the demo: 7 days).
- **Memory.** Proving in a desktop browser takes about 45 s and 5 GB, or about
  80 s and 2.6 GB on one thread. The one phone tried (8 cores, 8 GB or more)
  ran out of memory with several threads and proved in 79 s with one; phones
  with less memory are untested ([docs/circuit-spec.md](docs/circuit-spec.md),
  section 5).
- **Not every holder can prove:** photos above 924–987 bytes do not fit the
  circuit, the date of birth must be `DD-MM-YYYY`, the PIN code six digits, and
  the state name at most 31 characters.
- **Legal status.** Whether a website needs UIDAI's permission to use Secure QR
  this way is unsettled ([docs/issuer-research.md](docs/issuer-research.md),
  section 8).

## Trusted setup

The proving key is Anon Aadhaar's v2.0.0 key: a phase-2 ceremony with 105
contributions and a random beacon, on the Hermez Powers of Tau (2^20).
`snarkjs zkey verify` passes against the circuit rebuilt from source
(`packages/circuit/setup/verify-setup.sh`; circuit-spec, section 1). That shows
the ceremony ran as recorded, not that its participants were honest: proofs are
sound if at least one contributor destroyed their secret. zkID adds no setup of
its own.

## Layout

```
packages/secure-qr/        Secure QR parser and signature check, Node and browser; synthetic test codes
packages/circuit/          Anon Aadhaar's circuit artifacts, pinned by SHA-256; circuit input; tests, benchmarks
packages/issuer-registry/  UIDAI's keys with validity windows; refuses test and compromised keys in production
packages/verifier-sdk/     createRequest and verify, with typed failure codes (TypeScript)
frontend/                  The holder app (src/App.jsx, src/holder/), and the phone benchmark page (public/bench/)
apps/demo-rp/              Demo website: rules each visitor sets, request QR, verify, one account per nullifier; hosted demo for Vercel; end-to-end tests
attack-suite/              Tests of the attacks zkID does not defend; generates docs/ATTACK_REPORT.md
docs/                      Issuer research, threat model, attack report, circuit specification, decisions
tools/repo-checks/         No private key is tracked; the threat model is consistent
spike/                     Phase 1 measurements; a prototype for DigiLocker PAN records (spike/pan)
security/                  Keys whose private half is public; never trust them
```

## Run the demo

See [apps/demo-rp/README.md](apps/demo-rp/README.md): a local holder app, two
demo websites, and a synthetic QR signed by a TEST key generated on your
machine. Real QRs are never needed, and must never be committed.

The same README sets up the hosted demo: the holder app and two demo websites
in one Vercel project, which anyone can try with their own Aadhaar QR (read and
proved in their browser, never sent) or with a synthetic test QR the websites
make with a chosen gender, PIN code and state, signed by a TEST key that each
deployment makes. Each visitor sets a demo website's rules for their own
visit.

## Tests and the attack suite

```bash
(cd packages/secure-qr && npm test)         # parser, signature, synthetic codes, browser decoder
(cd packages/circuit && npm test)           # the circuit's controls on synthetic QRs (about 5 min; npm run fetch first)
(cd packages/issuer-registry && npm test)   # registry checks
(cd packages/verifier-sdk && npm test)      # every failure code, with real proofs
(cd frontend && npm test)                   # holder app: request and QR checks, circuit input
(cd apps/demo-rp && npm run test:e2e)       # seven proofs in headless Chromium, local and hosted builds, rules, network capture
(cd attack-suite && npm test)               # the attacks zkID does not defend, shown working
node attack-suite/report.mjs                # all of the above that the threat model cites -> docs/ATTACK_REPORT.md
node --test "tools/repo-checks/*.test.mjs"  # no private key tracked; threat model consistent
```

Run `npm install` in a package first. Several packages import
`packages/circuit`, so install it too. The end-to-end test needs Chromium
(`cd apps/demo-rp && npx playwright install chromium`). CI
([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs all of it, and fails
if the committed attack report differs from the one its run generates.
[attack-suite/README.md](attack-suite/README.md) has the details.

## Prior work

- [Anon Aadhaar](https://github.com/anon-aadhaar/anon-aadhaar) (PSE,
  MIT-licensed): the circuit, its proving key, the nullifier and the key-hash
  scheme. RSA verification of UIDAI's signature inside a circuit is theirs.
- [zk-email's circuits](https://www.npmjs.com/package/@zk-email/circuits)
  (RSA, SHA-256) and [circomlib](https://github.com/iden3/circomlib) (Poseidon,
  comparators), which that circuit is built from.
- [snarkjs](https://github.com/iden3/snarkjs) (Groth16) and the Hermez Powers of
  Tau; [poseidon-lite](https://www.npmjs.com/package/poseidon-lite) and
  [jsQR](https://github.com/cozmo/jsQR) in the holder app.
- UIDAI's Secure QR format and public certificates
  ([docs/issuer-research.md](docs/issuer-research.md)).

## v1

v1 (an OCR demo with its own issuer key, and Groth16 verifiers on Ethereum
Sepolia) is preserved at tag `v1-mock-issuer-demo`. Its Sepolia contracts are
retired but still deployed, and they accept forged proofs;
[SECURITY_NOTES.md](SECURITY_NOTES.md) lists them. v2 has no on-chain part:
[docs/DECISIONS.md](docs/DECISIONS.md) explains why, and what else was cut.

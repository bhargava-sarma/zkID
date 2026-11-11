# PAN prototype in Noir

The circom PAN circuit (`../pan`) rewritten in [Noir](https://noir-lang.org)
1.0.0 and proved with Barretenberg's UltraHonk (`@aztec/bb.js` 5.3.0), to see
whether a phone can prove claims from a DigiLocker PAN Verification Record
faster, in less memory, and without the circom version's 536 MB proving key and
setup ceremony. It is not wired into the SDK, the holder app or the demo.

## What the circuit proves

`circuit/src/main.nr` checks what `../pan/circuits/pan-verifier.circom`
checks (see `../pan/README.md` for the record's format):

- SHA-256 of the canonical record, as base64, in DigiLocker's exact
  `SignedInfo`; SHA-1 of that `SignedInfo` from the state after its constant
  first seven blocks; RSA PKCS#1 v1.5 with SHA-1 under the key;
- the record's fixed head: a PAN record, `status="A"`, issued through DigiLocker
  by the Income Tax Department;
- the date of birth, gender, `uid` and `<PAN>` attributes where the prover's
  hints point, each matched by its exact markup, the two PAN numbers equal, and
  all inside the hashed bytes.

It returns the key's hash, a per-verifier nullifier, the hour DigiLocker
verified the PAN (`YYYYMMDDHH`, IST), whether the holder was born on or before
`dob_cutoff`, and the gender if the holder reveals it. Its public inputs are
`dob_cutoff`, the nullifier seed and the signal hash.

How it differs from the circom version:

- **Hashes.** The key hash is Poseidon2 over the modulus's 18 limbs of 120
  bits, and the nullifier is `Poseidon2(seed, PAN, uid's two halves)`, both
  with Barretenberg's Poseidon2 (`poseidon2.nr`), not circomlib's Poseidon. A
  verifier pins DigiLocker's key by this hash.
- **RSA.** The prover supplies the quotient and remainder of each of the 17
  steps of `signature^65537 mod n` (`inputs.mjs`); the circuit checks each
  product limb by limb, carrying exactly between columns (`bignum.nr`).
- **SHA.** SHA-256 uses Noir's `sha256_compression` built-in; SHA-1 is written
  out (`sha1.nr`).
- **The hashed bytes.** The fields must lie inside the bytes SHA-256 covers.
  Writing this version showed that the circom one did not check that: for a
  signed record shorter than 1,280 bytes, a prover could have written the
  attributes after its end. `../pan` now checks it too; real records are about
  3 KB.

## Results

Measured on 2026-11-11 in a 4-core Intel Xeon container (2.3 GHz, 16 GB): Node
with bb.js's WebAssembly backend (what a browser runs), and headless Chromium
141 (`browser-bench.mjs`, the page in `web/`). The circom column is from
`../pan/README.md`, measured on the same kind of machine.

| | Noir, UltraHonk | circom, Groth16 (`../pan`) |
|---|---|---|
| Circuit | 333,411 gates | 1,989,686 constraints |
| Setup ceremony | none (Aztec's universal setup) | needed for production |
| Download for a first proof | about 25 MB: the page, the 1 MB circuit, 20 MB of setup points | 536 MB proving key, and the page |
| Node, 1 thread | 44 s, 1.1 GB | 105 s, 3.5 GB |
| Node, 4 threads | 16 s, 1.2 GB | 120 s, 6.7 GB |
| Chromium, 1 thread | 40 s, 0.9 GB | 118 s, 4.7 GB (4.1 GB of it anonymous) |
| Chromium, 4 threads | 20 s, 1.0 GB | 74 s, 9.0 GB |
| Proof | 14.6 KB | 0.8 KB |
| Building it | 4 s to compile | 2 minutes to compile, 18 for a dev setup |

Node's memory is the process's peak resident memory; Chromium's is the
browser's peak anonymous memory (`RssAnon`) for Noir, and resident memory for
circom, as `../pan` measured it. The witness takes under a second in both.

On a phone: pending. The test page is in `web/`, published at
https://bhargava-sarma.github.io/zkID-pan-bench/noir/.

Checked:

- **Synthetic records** (`npm test`, 7 tests, by executing the circuit, which
  checks every constraint): the outputs equal what `inputs.mjs` computes
  outside the circuit; every gender value; the date-of-birth cutoff to the
  day; the nullifier is stable for a PAN and uid and differs per verifier and
  per person; a changed byte, another key, another signature or a wrong hint
  fails; validly signed records outside the layout fail; and attributes written
  after a short record's hashed bytes fail.
- **The owner's real records** (the first download and the one fetched again
  nine days later; `PAN_XML=...`, run locally, nothing printed): accepted, with
  the outputs they should give.
- **Proofs** made in Node and in Chromium verify against the verification key
  (`web-data.mjs` computes it in Node; the page checks its proofs with it).

## Fitting it into the app

- **Holder app:** `noir_js` executes the circuit and `bb.js` proves, in the
  browser, as `web/main.js` does. Several threads need cross-origin isolation
  (COOP and COEP headers, which Vercel can send).
- **SDK:** `bb.js` verifies in Node with `UltraHonkVerifierBackend` and the
  circuit's verification key, and the issuer registry pins DigiLocker's key by
  its Poseidon2 hash.
- **Aadhaar stays as it is:** Groth16 for the Aadhaar QR, UltraHonk for PAN,
  each checked by its own verifier.

## Open questions, beyond `../pan`'s

1. **Versions.** Noir 1.0.0 was released the day before these measurements, and
   bb.js moves fast. The versions are pinned exactly; the verification key, and
   so the deployed verifier, changes with them.
2. **The setup points** come from Aztec's CDN (crs.aztec-cdn.foundation). The
   app could serve them itself.
3. **Review.** `bignum.nr`'s carries and `sha1.nr` are written by hand, and Noir
   and Barretenberg are new dependencies; both need a security review before
   real use.
4. **Proof size.** 14.6 KB instead of 0.8 KB: fine for a website, but larger
   to send and store.

## Run it

```bash
cd spike/pan && npm install                 # the record reader and synthetic records this uses
cd ../pan-noir && npm install
npm test                                     # constants check, then 7 tests on synthetic records
PAN_XML=<a real record, outside git> npm test   # also that record; nothing of it is printed
node bench.mjs [--single]                    # a proof in Node (WebAssembly), all cores or one
npm run web                                  # the test page, into build/web
node browser-bench.mjs [--single]            # the page in headless Chromium (apps/demo-rp's Playwright)
```

`browser-bench.mjs` serves Barretenberg's setup points from Node's cache
(`~/.bb-crs`, filled by any Node proof), since this sandbox's Chromium cannot
reach Aztec's CDN. Real records stay out of git.

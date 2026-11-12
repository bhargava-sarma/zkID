# Circuit specification

zkID proves statements about an Aadhaar Secure QR with **Anon Aadhaar's
published circuit, unchanged** (option A, chosen at stop gate 1; see
[issuer-research.md](issuer-research.md), section 9). The circuit is prior work
by PSE, MIT-licensed. zkID's v1 circuits are not used. This document records
what the circuit is, how its published artifacts were checked, what it enforces
and what it does not, and what it costs.

Code: [`packages/circuit`](../packages/circuit/README.md). The test IDs below
are those of [THREAT_MODEL.md](THREAT_MODEL.md).

Since 2026-11-12 zkID also proves statements about a DigiLocker PAN
Verification Record, with a circuit of its own: section 7.

## 1. Provenance and trusted setup

| | |
|---|---|
| Circuit | `AadhaarQRVerifier(121, 17, 1536)`, `packages/circuits/src/aadhaar-verifier.circom` in `anon-aadhaar/anon-aadhaar` at `b61b687` (2024-06-25); at `4dad918` (2025-04-19) it differs only in comments |
| Toolchain that reproduces the published key | circom 2.1.9 (`--O2`, its default), `@zk-email/circuits` 6.1.1, circomlib 2.0.5 |
| Size | 1,040,218 constraints, 1,026,196 wires, 394 template instances; 2^20 domain |
| Phase 1 of the setup | Hermez powers of tau, `powersOfTau28_hez_final_20.ptau`, BLAKE2b-512 `89a66eb5…2bf1a27b` as given in the snarkjs README |
| Phase 2 | 105 contributions and a beacon (contribution #106: generator `8636d0a8…ade9550`, 2^10 iterations) |
| Artifacts | v2.0.0 from `https://anon-aadhaar-artifacts.s3.eu-central-1.amazonaws.com/v2.0.0`, pinned by SHA-256 in [`artifacts.json`](../packages/circuit/artifacts.json) |

**`snarkjs zkey verify` passes** [M, 2026-10-26]: the pinned proving key
(SHA-256 `0d443ea8…6822c492`) matches the circuit rebuilt from source and the
Hermez file, with all 105 contributions and the beacon checked ("ZKey Ok!",
692 s, about 4 GB). Circuit hash `646b6c81 … e06351f9`. Full output:
[`setup/zkey-verify.txt`](../packages/circuit/setup/zkey-verify.txt). Repeat
it with `bash setup/verify-setup.sh`.

What this shows: the published key belongs to this circuit, and the ceremony's
transcript is internally consistent. It cannot show that any participant
destroyed their secret (assumption S3).

Two sourcing notes:

- The original hosts of the Hermez file (an AWS bucket and a Google Cloud
  bucket) now deny anonymous access. The file came from `circom.info`, the host
  the snarkjs README now links, and its BLAKE2b hash matches the README's.
- The proving key is also published as 10 gzip parts (296 MB in total). They
  decompress, in order, to the same SHA-256 as the 612 MB file. Their hashes
  are in `artifacts.json`; the browser can download the smaller form without
  trusting anything new.

## 2. Interface

Private inputs:

| Input | Size | Content |
|---|---|---|
| `qrDataPadded` | 1,536 bytes | the QR's signed data, SHA-256 padding, then zeros |
| `qrDataPaddedLength` | 1 | padded length, a multiple of 64 |
| `delimiterIndices` | 18 | positions of the first 18 `0xFF` delimiters |
| `signature` | 17 limbs of 121 bits | RSA signature |
| `pubKey` | 17 limbs of 121 bits | RSA modulus (e = 65537) |
| `revealAgeAbove18`, `revealGender`, `revealPinCode`, `revealState` | 1 each | 0 or 1. zkID's holder app sets a flag only for what the request's rules name |

Public inputs: `nullifierSeed` and `signalHash`. Outputs: `pubkeyHash`,
`nullifier`, `timestamp`, `ageAbove18`, `gender`, `pinCode`, `state`. snarkjs
returns the nine public signals in the order outputs, then public inputs:
`pubkeyHash, nullifier, timestamp, ageAbove18, gender, pinCode, state,
nullifierSeed, signalHash`.

## 3. What the circuit enforces

- **Signature.** SHA-256 over `qrDataPadded` up to `qrDataPaddedLength`, then RSA
  PKCS#1 v1.5 under `pubKey` (zk-email's `RSAVerifier65537`). Any changed signed
  byte, signature bit or key fails the witness (T1.2–T1.4).
- **Key hash.** `pubkeyHash` is Poseidon over the 17 key limbs merged in pairs
  (9 inputs). `keyHash()` in `packages/circuit` computes the same value; a test
  compares it with the circuit's output.
- **Delimiters.** The n-th `0xFF` before the photo is rewritten as n × 255, so a
  delimiter hint must point at the right occurrence. The circuit reads hints 3
  (date of birth), 10 and 11 (PIN code), 12 and 13 (state) and 17 (photo); a
  wrong value for any of them fails. The other twelve hints are never read
  (T7.6).
- **Timestamp.** Year, month, day and hour are read from **fixed byte positions**
  9–18, which assumes a two-byte version marker and a one-digit first field (true
  for V2 and V5). They are converted from IST to Unix time, rounded down to the
  hour.
- **Age.** The date of birth must be exactly 10 bytes (`DD-MM-YYYY`): the circuit
  checks for the delimiter 11 bytes after its start, so a year-only value fails
  (T1.8). The completed age on the QR's generation date is computed, and
  `ageAbove18 = age > 18`. **It is 1 only from the 19th birthday** (T1.10).
- **Nullifier.** `Poseidon(nullifierSeed, Poseidon(p[0..15]), Poseidon(p[16..31]))`,
  where `p` packs 992 bytes from the photo's first byte: the photo, the bytes
  after it (27 on V5), the SHA-256 padding, then zeros (T4.1, T5.1). The
  padding encodes the signed data's length, so a text field that changes
  length changes the nullifier too (T4.3).
- **Reveal flags** are constrained to 0 or 1, and each revealed output is
  multiplied by its flag. **`signalHash`** is squared in a constraint, so a
  proof is bound to it.
- **Gender, PIN code and state** are read whether or not they are revealed. The
  gender must be one byte; the output is its character code (77 for M). The
  PIN code must be six bytes; the output is its digits as a number (560034).
  The state must be at most 31 bytes (32 or more fails a comparator); the
  output packs its bytes into one integer, first byte lowest. A test in
  `packages/circuit` checks all three encodings, and that a longer state or a
  PIN code field of another length fails the witness.

## 4. What it does not enforce

These are inherited limits; THREAT_MODEL.md lists the ones that matter for
security.

- **Digits are not range-checked** in the date of birth or the timestamp. A
  month of 13 or a day of 32 is accepted; non-digit characters happen to fail in
  a comparator (T1.9). This is safe only because UIDAI signs the bytes.
- **The version marker is not checked.** V1 codes fail at the date-of-birth
  check; a future layout that keeps the same positions would be read as V2/V5.
- **Photo size.** The photo extractor accepts at most 1,023 bytes from the
  photo's first byte to the end of the SHA-padded data. With 27 trailing bytes
  the largest photo is 987 − ((1,023 + photo offset) mod 64) bytes, between 924
  and 987 (issuer-research section 7.4). Above it, a holder cannot prove at all.
  `buildInput` reports this as `PHOTO_TOO_LARGE` before any proving.
- **Only one age check**, against the QR's generation date, from the 19th
  birthday. No other cutoff is possible.
- **Values, not predicates.** Gender, PIN code and state are output as values,
  so a verifier's rule on one of them learns the value. PIN code digits are not
  range-checked either; the holder app refuses a PIN code rule on a QR whose PIN
  code is not six digits.
- **No key validity window in-circuit.** The verifier SDK compares `timestamp`
  with the key's window (Phase 4).
- **The timestamp is always public**, to the hour.

## 5. Cost

Measured on a 4-core Intel Xeon container (2.1 GHz, 16 GB), snarkjs 0.7.6:

| | Result |
|---|---|
| Download | wasm 10.5 MB; proving key 612 MB, or 296 MB as 10 gzip parts; verification key 4.4 KB |
| Node: witness | 2.8 s (median of 3) |
| Node: proof | 34.4 s (median of 3; 32.6–36.9 s), peak RSS 3.7 GB |
| Chromium, desktop, the benchmark page: download and unpack the proving key | 13–18 s for 296 MB from Anon Aadhaar's host, every file SHA-256-checked |
| Chromium, desktop, the benchmark page: witness + proof in a Web Worker | **44.3 s** (median of 3; 43.5–48.1 s); peak 4.7–4.9 GB across Chromium's processes |
| Chromium, desktop, the page's single-thread option | proving **77.7 s** (2 runs: 77.3, 78.2 s); peak **2.6 GB**, about half |
| Owner's Android phone (Android 10, Chrome 156, 8 cores, 8 GB or more; the browser hides the model), default (multi-threaded) | the proving key downloaded and unpacked; then **the tab crashed during proving** ("Aw, Snap!"), most likely out of memory (2026-10-26) |
| Same phone, the page's single-thread option | **proved**: proof **79.1 s**, 83.9 s end to end, verified (2026-10-26). The proving key loaded and unpacked in 3.2 s, most likely from the browser's cache of the earlier attempt |

Raw results: `packages/circuit/bench/results/` (`node.json`, `chromium.json`,
`chromium-single-thread.json`, `android-chrome-single-thread.json`).
Phase 1 measured the same artifacts at 3.4 s, 34.4 s and 51.8 s (main thread,
proving key served locally). The page's memory figure sums Chromium's
processes, so it overstates the true footprint somewhat. With several threads
that was too much for the phone tried; with one thread the same phone proved in
79 s. Phones with less memory are untested, so the holder app defaults to one
thread on phones.

## 6. Negative controls

`cd packages/circuit && npm test`, on synthetic V5 codes signed with ephemeral
keys:

| Test | Result |
|---|---|
| T1.2 one changed byte in 24 places: every field type, delimiters, photo start, middle and end, the trailing bytes, the SHA-256 padding | witness fails each time |
| T1.3 one changed signature bit (three limbs) | witness fails |
| T1.4 valid signature, another key | witness fails (RSA) |
| T1.7 an artifact whose SHA-256 differs from `artifacts.json` (vkey, wasm; junk file) | refused before use (`ARTIFACT_MISMATCH`) |
| T1.8 year-only date of birth | witness fails (`AgeExtractor`) |
| T1.9 month 13, day 32 / non-digits, `YYYY-MM-DD` | accepted / witness fails |
| T1.10 QR generated on, before and after the 18th and 19th birthdays | `ageAbove18 = 1` only from the 19th birthday; 0 with the age flag off |
| T4.1 same photo and trailing bytes, generated a day apart | same nullifier, different timestamp; other trailing bytes give another nullifier |
| T5.1 same QR, two seeds | different nullifiers |
| T7.1 each of the nine public signals changed after proving | verification fails; a verification key that is not the pinned one is refused |
| T7.6 delimiter hints 3, 10–13 and 17 shifted by ±1 / the other twelve shifted | witness fails / outputs unchanged |

## 7. The PAN circuit

zkID's own circuit for DigiLocker PAN Verification Records, in Noir 1.0.0,
proved with Barretenberg's UltraHonk (`@aztec/bb.js` 5.3.0, zero-knowledge, with
Poseidon2 for its transcript). Code: [`packages/pan`](../packages/pan/README.md)
(`circuit/src/main.nr`, with `sha1.nr`, `bignum.nr`, `poseidon2.nr` and the
generated `constants.nr`). It was written for this project and has not been
reviewed by anyone else (THREAT_MODEL, S13).

### 7.1 The record

DigiLocker issues the record after it checks a PAN with the Income Tax
Department. The XML is signed by DigiLocker (XML signature, enveloped): SHA-256
of the record's exclusive canonical form is the `DigestValue` in `SignedInfo`,
and `SignedInfo` is signed with RSA-2048, PKCS#1 v1.5 with SHA-1, under
DigiLocker's document-signing key. The record holds the PAN number, name, date
of birth, gender, a 32-hex `uid` (DigiLocker's id for the account) and
`verifiedOn`, when DigiLocker checked the PAN; its address fields are empty.
One record is about 3.2 KB of signed bytes, most of them a QR image.

The holder app reads the record (`packages/pan/record.mjs`, the same code in
Node): it canonicalizes it with zkID's exclusive-c14n (`c14n.mjs`, which matches
`xml-crypto` on synthetic records and on the owner's), checks the digest and
DigiLocker's signature against the keys it trusts, and checks the layout the
circuit reads, refusing anything else before proving.

### 7.2 Provenance and setup

| | |
|---|---|
| Compiled program | `artifacts/pan_verifier.json`, SHA-256 `e5a27464762d52f2d558865339b2d41c130a63f032d0f1137378c4725b94933f`, made by `build.mjs` with `@noir-lang/noir_wasm` 1.0.0 |
| Verification key | `artifacts/vk.json`, key SHA-256 `264ce5ceb9e566b56a08c8d18bb0536eb3d11832430b22d8550450c5aa26d27c`, pinned in the SDK, which checks it as it loads it (T1.17) |
| Reproducible | `npm run check` rebuilds both from `circuit/` and compares them byte for byte; CI runs it |
| Setup | none for this circuit: UltraHonk uses the BN254 points of Aztec's Ignition ceremony (THREAT_MODEL, S12). The prover downloads them from Aztec's CDN; the verifier embeds the two it needs, the generator and [x]₂, and Barretenberg checks [x]₂ against the SHA-256 it pins (`01797bfc…`) |

A new Noir or bb.js version changes the verification key, so the versions are
pinned exactly.

### 7.3 Interface

| | Name | Content |
|---|---|---|
| private | `doc` | the canonical record, SHA-256 padded, then zeros to 3,584 bytes (56 blocks) |
| private | `doc_padded_length` | its padded length |
| private | `signature`, `modulus` | 18 limbs of 120 bits each |
| private | `rsa_q`, `rsa_r` | quotient and remainder of each of the 17 multiplications of `signature^65537 mod n` |
| private | `gender_at`, `uid_at`, `pan_at` | where the gender, the Person's `uid` and `<PAN num=` start |
| private | `reveal_gender` | set by the holder app only when the request has a gender rule |
| public input | `dob_cutoff` | `YYYYMMDD`; the SDK requires the request's day in India, 19 years earlier |
| public input | `nullifier_seed`, `signal_hash` | as for a QR (THREAT_MODEL, section 1.1) |
| output | `pubkey_hash` | Poseidon2 of the modulus's 18 limbs |
| output | `nullifier` | Poseidon2 of the seed, the PAN number and the two halves of `uid` |
| output | `verified_hour` | `verifiedOn` to the hour, as `YYYYMMDDHH` (IST) |
| output | `born_by` | whether the date of birth is on or before `dob_cutoff` |
| output | `gender` | the character code of M, F or T if revealed, else 0 |

UltraHonk lists them as eight public inputs in the order `dobCutoff`,
`nullifierSeed`, `signalHash`, `pubkeyHash`, `nullifier`, `verifiedHour`,
`bornBy`, `gender` (`packages/pan/public.mjs`).

### 7.4 What it enforces

1. **The signature.** SHA-256 over the padded record, block by block up to
   `doc_padded_length`; its base64 inside DigiLocker's exact `SignedInfo`, of
   which every other byte is fixed (whitespace included); SHA-1 of that
   `SignedInfo`, from the state after its constant first seven blocks; and
   `signature^65537 = EM mod n`, where EM is the PKCS#1 v1.5 encoding of that
   SHA-1. Each multiplication is checked as `a × b = q × n + r` over the
   integers, limb by limb with exact carries, every limb range-checked.
2. **A PAN record.** The record's head is fixed byte for byte except the PAN
   number: `type="PANCR"`, `status="A"`, issued through DigiLocker by the
   Income Tax Department, then the date of birth as `DD-MM-YYYY` with digits.
3. **The fields.** The gender, `uid` and `<PAN>` attributes, in that order after
   the date of birth, each matched by its exact markup where the prover says
   it is; the gender is `MALE`, `FEMALE` or `TRANSGENDER`; `uid` is the Person's
   last attribute; the `<PAN>` element's number equals the head's; `verifiedOn`
   is `DD-MM-YYYY HH:MM:SS` with digits. All of them end within the first 1,280
   bytes and inside the hashed bytes. (Writing this circuit showed that the
   first version, in circom, did not check the last part: fields of a short
   record could be written after its end, where the signature does not reach.
   Both now check it, T1.14.)
4. **The outputs** as in 7.3; the gender only with `reveal_gender`.

### 7.5 What it does not enforce

- **Calendar ranges.** Day and month digits are not range-checked: month 13
  would pass if DigiLocker signed it (as T1.9 for a QR). This relies on
  DigiLocker's formatting (S10).
- **Which key.** It accepts any RSA key and outputs its hash; the SDK requires a
  registry key for PAN records (T1.12).
- **Freshness, age and rules** are the SDK's: it compares `verified_hour` with
  `maxAge`, requires `born_by` when the rules ask for age, and checks a revealed
  gender against the rules.
- **Other layouts.** The head, the 3,584-byte limit and the 1,280-byte window
  fit the records seen, all one person's; a long name, a larger QR image or an
  e-mail before the gender still fit. Other changes fail closed: the person
  cannot prove at all.

### 7.6 Cost

333,411 gates. Measured on 2026-11-11 (spike/pan-noir), Node with bb.js's
WebAssembly backend and headless Chromium 141 on a 4-core Intel Xeon container
(2.3 GHz, 16 GB), and on the owner's phone (8 cores, 8 GB or more, Android 16,
Chrome 156):

| | Proof | Peak memory |
|---|---|---|
| Node, 1 thread | 44 s | 1.1 GB |
| Node, 4 threads | 16 s | 1.2 GB |
| Chromium, 1 thread | 40 s | 0.9 GB |
| Chromium, 4 threads | 20 s | 1.0 GB |
| The owner's phone, 1 thread | 34.5 s | |
| The owner's phone, 8 threads | **13.6 s** | |

The witness takes under a second. The first proof downloads about 25 MB: the
page, the 0.7 MB program, and 20 MB of setup points (13.9 s on the phone; 1.3 s
the next time). A proof is 14,656 bytes, against 0.8 KB for a QR's. Checking one
takes milliseconds once Barretenberg has started. The holder app proves on up
to 8 threads when the page is cross-origin isolated, on one otherwise.

### 7.7 Negative controls

`cd packages/pan && npm test`, on synthetic records signed with ephemeral keys
(`PAN_XML=<files>` also runs the owner's real records, locally; nothing of them
is printed or committed):

| Test | Result |
|---|---|
| T1.13 a changed record byte, signature or key; a wrong field position | the reader refuses it before proving; the circuit fails |
| T1.14 another document type, status or issuer, two PAN numbers, an unknown gender or `uid`; fields after a short record's hashed bytes | the reader refuses them; the circuit fails |
| T1.15 born the day after, on and before the cutoff | `born_by` is 1 only on or before it |
| T1.17 the pinned verification key against the pinned program | both match their SHA-256 |
| T4.4, T5.5 the same PAN and `uid`; another verifier; another person | the same nullifier; another; another |
| T5.6, T6.1 every output, against what `input.mjs` computes outside the circuit | equal; the gender is 0 unless revealed |
| T7.7 a proof with any byte or public input changed | Barretenberg rejects it |
| T7.8 not XML, a DOCTYPE, namespaces, not a record | typed reader error |
| the owner's two records, verified nine days apart (`PAN_XML`, local) | accepted, with the outputs computed outside the circuit; both carry the same PAN and `uid`, so the same nullifier |

# Circuit specification

zkID proves statements about an Aadhaar Secure QR with **Anon Aadhaar's
published circuit, unchanged** (option A, chosen at stop gate 1; see
[issuer-research.md](issuer-research.md), section 9). The circuit is prior work
by PSE, MIT-licensed. zkID's v1 circuits are not used. This document records
what the circuit is, how its published artifacts were checked, what it enforces
and what it does not, and what it costs.

Code: [`packages/circuit`](../packages/circuit/README.md). The test IDs below
are those of [THREAT_MODEL.md](THREAT_MODEL.md).

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
| `revealAgeAbove18`, `revealGender`, `revealPinCode`, `revealState` | 1 each | 0 or 1. zkID's holder app sets only the age flag |

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
  after it (27 on V5), the SHA-256 padding, then zeros (T4.1, T5.1).
- **Reveal flags** are constrained to 0 or 1, and each revealed output is
  multiplied by its flag. **`signalHash`** is squared in a constraint, so a
  proof is bound to it.

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
| Mid-range phone | **not measured yet**: needs the owner's phone, through `frontend/public/bench/` |

Raw results: `packages/circuit/bench/results/` (`node.json`, `chromium.json`).
Phase 1 measured the same artifacts at 3.4 s, 34.4 s and 51.8 s (main thread,
proving key served locally). The page's memory figure sums Chromium's
processes, so it overstates the true footprint somewhat. A browser that needs
about 5 GB on a desktop is a real risk on a phone.

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

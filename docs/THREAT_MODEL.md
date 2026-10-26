# Threat model

Phase 2 of the v2 overhaul. It covers the design the owner chose at stop gate 1
(option A, 2026-10-26): Anon Aadhaar's published circuit, unchanged, with
zkID's request protocol, verifier SDK, issuer registry and holder app around it
([issuer-research.md](issuer-research.md), section 9).

**Status:** every test in section 7 exists and passes. Phase 6 added the tests
that show the undefended attacks succeeding, and
[ATTACK_REPORT.md](ATTACK_REPORT.md) is generated from a run of all of them
(`attack-suite/report.mjs`). Phase 6 also found attack A4.6.

## 1. System

The thesis, from the brief: "An adult can prove 'I am 18 or older' to a
specific website, using a credential signed by the real identity authority, in
a way that cannot be replayed to another verifier, cannot create more than one
account per site per credential, cannot be linked across sites, and never
reveals anything else - with a published list of what is and is not defended."

Parts:

- **Holder app**, a static web page. It reads the holder's Aadhaar Secure QR
  from an image (e.g. a screenshot of e-Aadhaar), fetches the verifier's
  request, proves in a web worker and posts the proof to the verifier. It never
  sends the QR anywhere.
- **Circuit**: Anon Aadhaar's `AadhaarQRVerifier(121, 17, 1536)`, its published
  v2.0.0 artifacts, pinned by SHA-256. zkID does not modify it.
- **Verifier SDK**: `createRequest` and `verify`, with typed failure codes.
- **Issuer registry**: UIDAI certificates with their validity windows, each
  stored with the Poseidon key hash that the circuit outputs.
- **Demo relying party**: an age-gated page that uses the SDK.

### 1.1 What the verifier receives

A proof has nine public signals:

| Signal | Kind | Content | Check in `verify` (failure code) |
|---|---|---|---|
| `pubkeyHash` | output | Poseidon hash of the RSA key that signed the QR | in the registry (`UNTRUSTED_ISSUER`), and `timestamp` inside that key's validity window (`ISSUER_KEY_NOT_VALID`) |
| `nullifier` | output | hash of `nullifierSeed` and the bytes from the photo to the end of the SHA-padded data | not seen before at this verifier (`NULLIFIER_SEEN`) |
| `timestamp` | output | QR generation time, rounded down to the hour (IST), as Unix time | not older than the request's `maxAge` (`CREDENTIAL_TOO_OLD`) |
| `ageAbove18` | output | 1 if the holder's completed age on the QR's generation date was above 18 (that is, from their 19th birthday) and the prover revealed it; otherwise 0 | equals 1 (`AGE_NOT_PROVEN`) |
| `gender`, `pinCode`, `state` | outputs | 0 unless the prover revealed them | the holder app always sends 0 (A6.1) |
| `nullifierSeed` | public input | per-verifier value | equals this verifier's seed (`NULLIFIER_SEED_MISMATCH`) |
| `signalHash` | public input | value the proof commits to | equals the hash of the stored request (`CHALLENGE_MISMATCH`) |

`verify` also checks the Groth16 proof against the pinned verification key
(`BAD_PROOF`), and that the request's challenge is unused (`CHALLENGE_REUSED`)
and unexpired (`CHALLENGE_EXPIRED`). The reveal flags are private inputs, so a
verifier sees only the outputs.

### 1.2 Decisions made in this document

The brief leaves these open. The owner accepted all four on 2026-10-26; Phases 4
and 5 implement them.

1. **The verifier id is the verifier's HTTPS origin.** The request QR or link
   holds a URL on that origin. The holder app fetches the request from it and
   posts the proof back to the same origin. TLS then authenticates the id,
   instead of the holder app trusting whatever a QR says. `nullifierSeed` is a
   hash of the id; `signalHash` is a hash of the whole request (id, challenge,
   `maxAge`, expiry).
2. **Failure codes.** The brief's `CUTOFF_TOO_LATE` has no meaning under option
   A, where the circuit fixes the cutoff at 18; `AGE_NOT_PROVEN` replaces it.
   Added: `ISSUER_KEY_NOT_VALID` and `NULLIFIER_SEED_MISMATCH`.
3. **Replay detection keys on the challenge, never on proof bytes,** because a
   Groth16 proof can be re-randomized into different bytes with the same public
   signals.
4. **The holder app, not the SDK, limits disclosure.** A malicious verifier
   controls its own SDK.

## 2. Assumptions

| | Assumption | Evidence or status | If it fails |
|---|---|---|---|
| S1 | **Issuer honesty.** UIDAI signs only data it holds for that person, keeps its signing keys secret, and issues one Aadhaar number per person. | Not checkable by zkID. | Forgery (G1) or extra accounts (G3), undetectable. |
| S2 | **Key authenticity.** The registry's certificates are UIDAI's. | DS 06 (2026–2029): downloaded from UIDAI by the owner, fingerprint matches an independent project's, and the owner's QR verifies under it. Older keys: copies from other projects; all have expired. | A fake key is trusted. |
| S3 | **Setup.** At least one participant in Anon Aadhaar's v2.0.0 ceremony (105 phase-2 contributions plus a beacon, on the Hermez powers of tau) destroyed their secret. | `snarkjs zkey verify` passes (Phase 3): the pinned proving key matches the circuit rebuilt from source and the Hermez powers of tau, with all 105 contributions and the beacon checked (docs/circuit-spec.md, section 1). This shows the ceremony was carried out as recorded; it cannot show that any participant was honest. | Proofs can be forged for any statement. |
| S4 | **Circuit correctness.** The published circuit enforces what its source says. | The proving key reproduces from the June 2024 source (Phase 1). PSE audited an earlier commit (`bbdfd9d`, March 2024); later changes were not reviewed here, and zkID does not re-audit. The circuit does not range-check DOB or timestamp digits and relies on UIDAI's formatting (T1.9). | Depends on the flaw. |
| S5 | **Verifier clock** is accurate to a few minutes. | Assumed. The QR timestamp has one-hour resolution, so freshness is coarse anyway. | Expired challenges or stale QRs accepted, or valid ones rejected. |
| S6 | **Verifier state.** The verifier binds each request to the session that created it, and durably stores used challenges and seen nullifiers. | The demo relying party must show it. | Replay (G2) or extra accounts (G3). |
| S7 | **Holder environment.** The holder app's code is served unmodified, and the holder's device is not compromised. | Static build; artifacts pinned by SHA-256. A malicious host or device can read the QR. | G6 fails. |
| S8 | **Stable nullifier material.** The photo and the bytes after it are the same on every download of the same person's QR. | One holder, two downloads 26.8 hours apart: identical (issuer-research, section 6). Other sources (PVC card, Aadhaar app, printed letter) untested. | A re-download gives another account (G3). |
| S9 | **Cryptography.** RSA-2048 PKCS#1 v1.5 with SHA-256, Poseidon, and Groth16 on BN254 (about 100-bit security) hold. | Standard assumptions. | Everything. |

## 3. Adversaries

From the brief:

| | Adversary | Has | Wants |
|---|---|---|---|
| A1 | Forger | no UIDAI-signed QR, or one that does not show 18+ | an accepted proof |
| A2 | Replayer | someone else's proof: captured, screenshotted, or relayed live | acceptance at another verifier, or later |
| A3 | Lender | an adult's QR, given to a minor | accounts for the minor |
| A4 | Sybil | their own QR | several accounts at one verifier |
| A5 | Linker | records of two or more colluding verifiers | to tell whether two proofs came from one person |
| A6 | Malicious verifier | a request the holder will answer | more than "18+" |
| A7 | Tamperer | write access to the QR, proof, public signals or request in transit | any accepted change |

## 4. Goals

| Goal | Status under option A | How | Tests |
|---|---|---|---|
| G1 Unforgeability | **Yes**, under S1–S4 | SHA-256 and RSA over all signed bytes in-circuit; key hash in the registry; timestamp inside the key's window; pinned artifacts | T1.1–T1.10, T7.1–T7.3, T7.5, T7.6 |
| G2 Verifier binding | **Yes** for replay; **No** for live relay (A2.5) | `signalHash` is a hash of the request; challenges are single-use and short-lived | T2.1–T2.6, T7.4 |
| G3 Per-verifier uniqueness | **Partly** | per-verifier `nullifierSeed`; nullifier from the photo bytes, the bytes after them and the signed data's length. Fails on a photo update, on any update that changes the signed data's length, possibly on QRs from other sources, and against anyone who holds the QR | T2.5, T3.1, T3.2, T3.4, T4.1–T4.3, T5.1, T5.2, T5.4 |
| G4 Freshness | **Yes**, to the hour | the SDK compares the public `timestamp` with the request's `maxAge` | T3.3, T3.5 |
| G5 Minimal disclosure | **Partly**: the QR's generation hour and the UIDAI key are also revealed | the holder app sets only the age reveal flag | T1.10, T5.3, T6.1, T6.2 |
| G6 Client-side only | **Yes**, under S7 | the holder app proves locally and sends only the proof | T6.3 |

The brief put the freshness check (`minCredentialDate`) inside the circuit.
Under option A the SDK makes the same check on a public timestamp, and that
public timestamp is what costs G5.

So the thesis holds with the two qualifiers of issuer-research section 9: "one
account per site per credential" fails across a photo update (and, Phase 6
found, across any update that changes the signed data's length, A4.6), and
"cannot be linked across sites" holds only against parties who have not seen
the person's QR. Option A adds a third: "I am 18 or older" can only be proved
from the 19th birthday, because the circuit's `ageAbove18` means a completed
age above 18.

## 5. Attacks

"Yes" means the mechanism rejects the attack. **No** means it succeeds;
where a test is listed, the test shows it succeeding.

| | Attack | Defended? | Mechanism | Tests |
|---|---|---|---|---|
| A1.1 | Sign a QR with your own RSA key | Yes | the circuit accepts any key but outputs its hash; the SDK requires a registry key | T1.1 |
| A1.2 | Change bytes of a genuine QR, e.g. the DOB | Yes | SHA-256 and RSA over every signed byte | T1.2, T7.3 |
| A1.3 | Change the signature, or check it under another key | Yes | RSA check | T1.3, T1.4 |
| A1.4 | Get a test key into a production registry | Yes | the production build fails if one is present | T1.5 |
| A1.5 | Sign with an old UIDAI key that leaks after it expires | Yes, once the key has been expired for longer than `maxAge` | the timestamp must be inside the key's window and within `maxAge` | T1.6, T3.3 |
| A1.6 | Sign with UIDAI's current key | **No** | assumption S1 | none |
| A1.7 | Swap the verification key, circuit artifacts or registry | Yes | pinned by SHA-256 at build time | T1.7 |
| A1.8 | Forge a proof without a valid witness | Yes, under S3 and S9 | Groth16 soundness | none (assumption) |
| A1.9 | Use a genuine QR of someone under 18, or hide the age bit | Yes | `ageAbove18` must be 1, which the circuit outputs only from the 19th birthday | T1.10 |
| A1.10 | Exploit unusual signed data: a DOB not in `DD-MM-YYYY`, or non-digits | Partly | fails closed when the DOB is not 10 bytes (the circuit checks the delimiter 11 bytes after its start); digits are not range-checked, so this relies on UIDAI's formatting (S4) | T1.8, T1.9 |
| A2.1 | Submit a captured proof to another verifier | Yes | different `signalHash` and `nullifierSeed` | T2.1, T2.5 |
| A2.2 | Submit it again to the same verifier | Yes | single-use challenge | T2.2 |
| A2.3 | Re-randomize the proof and resubmit | Yes | replay detection keys on the challenge | T2.3 |
| A2.4 | Submit after the request expired | Yes | short-lived challenge | T2.4 |
| A2.5 | Relay a verifier's live request to a victim, and use the victim's proof for your own session | **No** | the proof is bound to the request, not to who holds the session at the verifier; the holder app shows the verifier's origin, which helps only a careful user | T2.6 |
| A3.1 | Lend an adult's QR to a minor: one account per site | **No** | non-goal; preventing it needs biometrics | T3.1 |
| A3.2 | Use the lent QR for a second account at the same site | Yes | same nullifier | T3.2 |
| A3.3 | Use a photocopy of someone else's QR | **No** for recent QRs; Yes for QRs older than `maxAge` | nothing binds the proof to the holder; freshness rejects old letters and old copies | T3.3, T3.5 |
| A3.4 | Update the photo to get another slot | **No** | a new photo gives a new nullifier (Anon Aadhaar audit, High, no fix) | T3.4 |
| A4.1 | Re-download the QR for a second account | Yes, for the one holder tested (S8) | the same photo and trailing bytes give the same nullifier | T4.1 |
| A4.2 | Prove under a different `nullifierSeed` | Yes | the SDK requires its own seed | T2.5 |
| A4.3 | Use QRs from other sources or format versions | Partly | unknown whether a PVC card or the Aadhaar app carries the same bytes; a code with V1's 64 bytes after the photo gives a different nullifier than one with V5's 27, and a V1 code cannot be proved at all; freshness rejects old letters | T4.2, T3.3 |
| A4.4 | Update the photo | **No** | as A3.4 | T3.4 |
| A4.5 | Hold two Aadhaar numbers | **No** | relies on UIDAI's de-duplication (S1) | none |
| A4.6 | Change the length of any signed field, e.g. by an address update, for another slot | **No** | the nullifier covers the SHA-256 padding after the photo, which encodes the signed data's length (found in Phase 6) | T4.3 |
| A5.1 | Compare nullifiers across sites | Yes, against parties without the QR | different seeds; the photo's ~900 bytes cannot be guessed | T5.1 |
| A5.2 | Compute someone's nullifier for every site from their QR (anyone with a copy, or UIDAI) | **No** | the photo is not secret | T5.2 |
| A5.3 | Match the QR's generation hour and key hash across sites | **No** under option A | both are public outputs; a holder who uses a separate fresh QR per site avoids matching hours | T5.3 |
| A5.4 | Correlate IP addresses or timing | **No** | out of scope | none |
| A5.5 | Request a proof under another site's id, to learn the user's nullifier there | Yes | the id is the origin the request came from (decision 1) | T5.4 |
| A6.1 | Ask the holder app to reveal gender, PIN code or state | Yes | the app refuses, and always sets those reveal flags to 0 | T6.1, T6.2 |
| A6.2 | Learn the DOB or exact age | Yes | only the 18+ bit is output | T6.1 |
| A6.3 | Learn the QR's generation hour and UIDAI key | **No** under option A | always public | T5.3 |
| A6.4 | Get the QR itself | Yes, under S7 | the app never sends it | T6.3 |
| A7.1 | Flip a signed byte of the QR | Yes | as A1.2 | T1.2, T7.3 |
| A7.2 | Change a public signal after proving | Yes | Groth16 verification | T7.1 |
| A7.3 | Change proof bytes | Yes | Groth16 verification; a re-randomized proof stays valid (A2.3) | T7.2 |
| A7.4 | Change the request in transit | Yes | fetched over TLS from the verifier's origin; `signalHash` must match the stored request | T7.4 |
| A7.5 | Send malformed QR text | Yes | the parser fails with a typed error and never falls back | T7.5 |
| A7.6 | Give wrong delimiter positions | Yes | the circuit checks each delimiter's position | T7.6 |

## 6. Non-goals and accepted limits

- **Lending and impersonation** (A3.1, A3.3) beyond one account per site per
  QR. Preventing them needs biometrics or liveness.
- **Full KYC**: address, AML screening, liveness.
- **Name and gender proofs**: removed.
- **18-year-olds, and any other cutoff** (accepted by the owner at stop gate 3,
  2026-10-26). Under option A the circuit only outputs "completed age above 18
  on the QR's generation date", which becomes true on the 19th birthday. Holders
  aged 18 cannot prove until then (T1.10).
- **Hiding the QR's generation hour and the UIDAI key** from verifiers (A5.3,
  A6.3).
- **Revocation.** Secure QR has none; freshness is the only control.
- **Network anonymity** (A5.4) and **denial of service**.
- **Every holder.** Photos above 924–987 bytes cannot be proved
  (issuer-research, section 7.4), a DOB not in `DD-MM-YYYY` fails (T1.8), and
  proving in a desktop browser needs about 5 GB of memory (2.6 GB on one
  thread). The one phone tried ran out of memory with several threads and
  proved in 79 s with one; phones with less memory are untested
  ([circuit-spec.md](circuit-spec.md), section 5).
- **Novelty.** RSA in a circuit, the circuit itself and the nullifier
  construction are Anon Aadhaar's. zkID contributes the request protocol, the
  seed and freshness policy, the key registry with validity windows, the SDK,
  the holder app and the attack suite.
- **Legal clearance.** Whether a verifier must register with UIDAI is unsettled
  (issuer-research, section 8). This is a research prototype.

## 7. Tests

"Phase" is where a test was first implemented; `attack-suite/report.mjs` runs
them all and writes [ATTACK_REPORT.md](ATTACK_REPORT.md). Synthetic QRs are
signed with ephemeral test keys.

| Test | Phase | Input | Expected | Evidence |
|---|---|---|---|---|
| T1.1 | 4 | valid proof from a QR signed with a fresh key | `UNTRUSTED_ISSUER` | passes in `packages/verifier-sdk` tests |
| T1.2 | 3 | one byte changed in each text field, each delimiter, the start, middle and end of the photo, and the trailing bytes | witness generation fails | passes in `packages/circuit` tests; Phase 1: `check_controls.mjs` (one DOB byte, one photo byte) |
| T1.3 | 3 | one signature bit changed | witness generation fails | passes in `packages/circuit` tests; Phase 1: `check_controls.mjs` |
| T1.4 | 3 | valid signature, another key as input | witness generation fails | passes in `packages/circuit` tests; Phase 1: `check_controls.mjs` |
| T1.5 | 4 | production build with a test key in the registry | build fails | passes in `packages/issuer-registry` tests |
| T1.6 | 4 | registry key, `timestamp` outside its validity window | `ISSUER_KEY_NOT_VALID` | passes in `packages/verifier-sdk` tests |
| T1.7 | 3 | one byte changed in the wasm, proving key or verification key | rejected on load (SHA-256 mismatch) | passes in `packages/circuit` tests |
| T1.8 | 3 | DOB field of 4 bytes (year only) | witness generation fails | passes in `packages/circuit` tests |
| T1.9 | 3 | DOB of 10 bytes with non-digits | outputs recorded; documents the missing range check | passes in `packages/circuit` tests |
| T1.10 | 3 and 4 | QR generated the day before, on, and after the holder's 18th and 19th birthdays; an adult with the age flag off | `ageAbove18` is 1 only on and after the 19th birthday (Phase 3); `AGE_NOT_PROVEN` for every 0 (Phase 4) | passes in `packages/circuit` and `packages/verifier-sdk` tests; Phase 1: `check_controls.mjs` (under 18; flag off) |
| T2.1 | 4 | proof for verifier X sent to verifier Y | `CHALLENGE_MISMATCH` | passes in `packages/verifier-sdk` tests |
| T2.2 | 4 | the same proof sent twice to X | second: `CHALLENGE_REUSED` | passes in `packages/verifier-sdk` tests |
| T2.3 | 4 | re-randomized copy of an accepted proof | `CHALLENGE_REUSED` | passes in `packages/verifier-sdk` tests |
| T2.4 | 4 | proof sent after the request expired | `CHALLENGE_EXPIRED` | passes in `packages/verifier-sdk` tests |
| T2.5 | 4 | proof under another `nullifierSeed` | `NULLIFIER_SEED_MISMATCH` | passes in `packages/verifier-sdk` tests |
| T2.6 | 6 | request from the attacker's session, proved by the victim | accepted (not defended) | passes in `attack-suite` tests |
| T3.1 | 6 | lent QR, first account | accepted (not defended); the QR's owner is then `NULLIFIER_SEEN` | passes in `attack-suite` tests |
| T3.2 | 4 | lent QR, second account at the same site | `NULLIFIER_SEEN` | passes in `packages/verifier-sdk` tests |
| T3.3 | 4 | QR older than `maxAge` | `CREDENTIAL_TOO_OLD` | passes in `packages/verifier-sdk` tests |
| T3.4 | 6 | same identity, new photo bytes | new nullifier; second account accepted (not defended) | passes in `attack-suite` tests |
| T3.5 | 4 | QR exactly `maxAge` old, and one hour older | accepted, then `CREDENTIAL_TOO_OLD` | passes in `packages/verifier-sdk` tests |
| T4.1 | 3 | two downloads: same photo and trailing bytes, different generation time | equal nullifiers; second account `NULLIFIER_SEEN` | passes in `packages/circuit` and `packages/verifier-sdk` tests; Phase 1: `check_controls.mjs`; the owner's two real downloads, by byte comparison |
| T4.2 | 6 | the same photo followed by V1's 64 bytes (in a V2-layout code, as in Anon Aadhaar's V2 test data) and by V5's 27; a V1 code | different nullifiers (documents A4.3); the V1 code is refused (`UNSUPPORTED_LAYOUT`) | passes in `attack-suite` tests |
| T4.3 | 6 | same photo and trailing bytes; one field one byte longer, then one changed without changing its length | new nullifier and a second account accepted (documents A4.6); the same nullifier | passes in `attack-suite` tests |
| T5.1 | 3 | same QR, two verifier ids | different nullifiers | passes in `packages/circuit` tests; Phase 1: `check_controls.mjs` |
| T5.2 | 6 | only a copy of the QR | its nullifier for any verifier id, computed offline, matches the holder's (documents A5.2) | passes in `attack-suite` tests (computed with the circuit's witness generator) |
| T5.3 | 6 | the same QR at two verifiers | identical `timestamp` and `pubkeyHash` (documents A5.3) | passes in `attack-suite` tests |
| T5.4 | 5 | request served from origin B naming verifier A | holder app refuses | passes in `frontend/src/holder` tests (`WRONG_ORIGIN`) |
| T6.1 | 5 | every proof the holder app makes | exactly the nine signals of section 1.1; `gender`, `pinCode` and `state` are 0 | passes in `frontend/src/holder` tests (the circuit input) and the `apps/demo-rp` end-to-end test (every proof posted) |
| T6.2 | 5 | request asking for gender, PIN code or state | holder app refuses with a typed error | passes in `frontend/src/holder` tests (`UNSUPPORTED_REQUEST`) |
| T6.3 | 5 | full flow under network capture | no request carries the QR digits, its bytes, the photo or any field value | passes in the `apps/demo-rp` end-to-end test: headless Chromium, every request of the pages and the proving worker captured |
| T7.1 | 3 and 4 | each public signal changed after proving | Groth16 verification fails (Phase 3); `BAD_PROOF`, except `nullifierSeed` and `signalHash`, which the SDK checks first: `NULLIFIER_SEED_MISMATCH`, `CHALLENGE_MISMATCH` (Phase 4) | passes in `packages/circuit` and `packages/verifier-sdk` tests |
| T7.2 | 4 | each proof element changed | `BAD_PROOF` | passes in `packages/verifier-sdk` tests |
| T7.3 | 5 | every signed byte of a synthetic V5 QR flipped, one at a time, in the holder app's parser | signature check fails before proving | passes in `packages/secure-qr` tests (`web.mjs`, the holder app's parser) |
| T7.4 | 4 | `verifierId`, challenge or `maxAge` changed after proving | `CHALLENGE_MISMATCH` | passes in `packages/verifier-sdk` tests |
| T7.5 | 5 | malformed QR text: not decimal, bad compression, unknown version, truncated | typed parser error | passes in `packages/secure-qr` tests, for the Node parser and the holder app's (`web.mjs`) |
| T7.6 | 3 | delimiter positions shifted | witness generation fails | passes in `packages/circuit` tests; Phase 1: `check_controls.mjs` (DOB hint) |

`tools/repo-checks/threat_model.test.mjs` checks this document: every goal
lists a test, every test cited exists in this table, and every test in this
table serves a goal.

## 8. Open questions that would change rows

- Do QRs from the PVC card, the Aadhaar app and printed letters carry the same
  photo and trailing bytes as e-Aadhaar? (A4.3, S8)
- What are the 27 bytes after the photo? If UIDAI changes them, every V5
  nullifier changes. (S8)
- How large are real photos? Above 924–987 bytes a holder cannot prove at all.
- What do QRs of holders with only a year of birth contain? (T1.8)
- Can a phone with less than 8 GB of memory prove? An 8-core phone with 8 GB
  or more proved in 79 s on one thread (circuit-spec, section 5).
- Does a verifier need UIDAI registration? (issuer-research, section 8)

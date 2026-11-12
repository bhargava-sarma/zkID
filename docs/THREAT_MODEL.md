# Threat model

Phase 2 of the v2 overhaul. It covers the design the owner chose at stop gate 1
(option A, 2026-10-26): Anon Aadhaar's published circuit, unchanged, with
zkID's request protocol, verifier SDK, issuer registry and holder app around it
([issuer-research.md](issuer-research.md), section 9).

**Status:** every test in section 7 exists and passes. Phase 6 added the tests
that show the undefended attacks succeeding, and
[ATTACK_REPORT.md](ATTACK_REPORT.md) is generated from a run of all of them
(`attack-suite/report.mjs`). Phase 6 also found attack A4.6. On 2026-10-27,
after the overhaul, the owner added rules on gender, PIN code and state
(decision 5); tests from that change say 9 in the Phase column. On
2026-11-12 the owner added a second credential, DigiLocker's PAN Verification
Record, proved with zkID's own circuit (decision 6); its tests say 10.

## 1. System

The thesis, from the brief: "An adult can prove 'I am 18 or older' to a
specific website, using a credential signed by the real identity authority, in
a way that cannot be replayed to another verifier, cannot create more than one
account per site per credential, cannot be linked across sites, and never
reveals anything else - with a published list of what is and is not defended."

Parts:

- **Holder app**, a static web page. It reads the holder's Aadhaar Secure QR
  from an image (e.g. a screenshot of e-Aadhaar), or the XML of their DigiLocker
  PAN Verification Record, fetches the verifier's request, proves on the device
  and posts the proof to the verifier. It never sends the QR or the record
  anywhere.
- **Circuits**: for a QR, Anon Aadhaar's `AadhaarQRVerifier(121, 17, 1536)`,
  its published v2.0.0 artifacts, pinned by SHA-256; zkID does not modify it.
  For a PAN record, zkID's own circuit in Noir 1.0.0 (`packages/pan`), proved
  with Barretenberg's UltraHonk (bb.js 5.3.0); its compiled program and
  verification key are pinned by SHA-256, and it needs no setup ceremony of its
  own ([circuit-spec.md](circuit-spec.md), section 7).
- **Verifier SDK**: `createRequest` and `verify`, with typed failure codes.
- **Issuer registry**: UIDAI's certificates and DigiLocker's document-signing
  key, each with its validity window, the credential it signs, and the key hash
  that credential's circuit outputs.
- **Demo relying party**: a page that uses the SDK, with rules each visitor
  sets.

### 1.1 What the verifier receives

An Aadhaar proof has nine public signals:

| Signal | Kind | Content | Check in `verify` (failure code) |
|---|---|---|---|
| `pubkeyHash` | output | Poseidon hash of the RSA key that signed the QR | in the registry (`UNTRUSTED_ISSUER`), and `timestamp` inside that key's validity window (`ISSUER_KEY_NOT_VALID`) |
| `nullifier` | output | hash of `nullifierSeed` and the bytes from the photo to the end of the SHA-padded data | not seen before at this verifier (`NULLIFIER_SEEN`) |
| `timestamp` | output | QR generation time, rounded down to the hour (IST), as Unix time | not older than the request's `maxAge` (`CREDENTIAL_TOO_OLD`) |
| `ageAbove18` | output | 1 if the holder's completed age on the QR's generation date was above 18 (that is, from their 19th birthday) and the prover revealed it; otherwise 0 | equals 1 when the request's rules ask for it (`AGE_NOT_PROVEN`) |
| `gender`, `pinCode`, `state` | outputs | 0 unless the prover revealed them. Revealed: the gender's character code (M, F or T), the PIN code's six digits as a number, and up to 31 bytes of the state's name packed into one integer | with a rule on the field in the request, its value is one the rule accepts (`GENDER_NOT_ALLOWED`, `PIN_CODE_NOT_ALLOWED`, `STATE_NOT_ALLOWED`); the holder app reveals a field only when the request has a rule on it (A6.1) |
| `nullifierSeed` | public input | per-verifier value | equals this verifier's seed (`NULLIFIER_SEED_MISMATCH`) |
| `signalHash` | public input | value the proof commits to | equals the hash of the stored request (`CHALLENGE_MISMATCH`) |

`verify` also checks the Groth16 proof against the pinned verification key
(`BAD_PROOF`), and that the request's challenge is unused (`CHALLENGE_REUSED`)
and unexpired (`CHALLENGE_EXPIRED`), and that the request accepts QRs
(`DOCUMENT_NOT_ACCEPTED`). The reveal flags are private inputs, so a verifier
sees only the outputs.

A PAN proof has eight public inputs; UltraHonk makes the circuit's outputs
public inputs too:

| Input | Kind | Content | Check in `verify` (failure code) |
|---|---|---|---|
| `dobCutoff` | input | the latest date of birth that counts as 19 or older, as `YYYYMMDD` | equals the request's day in India, 19 years earlier (`CHALLENGE_MISMATCH`) |
| `nullifierSeed` | input | per-verifier value | as for a QR (`NULLIFIER_SEED_MISMATCH`) |
| `signalHash` | input | value the proof commits to | as for a QR (`CHALLENGE_MISMATCH`) |
| `pubkeyHash` | output | Poseidon2 hash of the RSA key that signed the record | in the registry as a key for PAN records (`UNTRUSTED_ISSUER`), and `verifiedHour` inside that key's validity window (`ISSUER_KEY_NOT_VALID`) |
| `nullifier` | output | Poseidon2 hash of `nullifierSeed`, the PAN and the record's `uid` (32 hex digits, DigiLocker's id for the account) | not seen before at this verifier for a PAN record (`NULLIFIER_SEEN`); the two credentials' nullifiers are kept apart |
| `verifiedHour` | output | when DigiLocker last verified the PAN with the Income Tax Department, to the hour (IST), as `YYYYMMDDHH` | not older than the request's `maxAge` (`CREDENTIAL_TOO_OLD`) |
| `bornBy` | output | 1 if the date of birth is on or before `dobCutoff` | equals 1 when the request's rules ask for 19 or older (`AGE_NOT_PROVEN`) |
| `gender` | output | 0 unless the prover revealed it; revealed, the character code of M, F or T | as for a QR (`GENDER_NOT_ALLOWED`) |

`verify` checks the UltraHonk proof against the pinned verification key
(`BAD_PROOF`), the challenge as for a QR, and that the request accepts PAN
records (`DOCUMENT_NOT_ACCEPTED`).

### 1.2 Decisions made in this document

The brief leaves the first four open. The owner accepted them on 2026-10-26;
Phases 4 and 5 implement them. The fifth came on 2026-10-27, the sixth on
2026-11-12.

1. **The verifier id is the verifier's HTTPS origin.** The request QR or link
   holds a URL on that origin. The holder app fetches the request from it and
   posts the proof back to the same origin. TLS then authenticates the id,
   instead of the holder app trusting whatever a QR says. `nullifierSeed` is a
   hash of the id; `signalHash` is a hash of the whole request (id, challenge,
   `maxAge`, expiry, rules).
2. **Failure codes.** The brief's `CUTOFF_TOO_LATE` has no meaning under option
   A, where the circuit fixes the cutoff at 18; `AGE_NOT_PROVEN` replaces it.
   Added: `ISSUER_KEY_NOT_VALID` and `NULLIFIER_SEED_MISMATCH`.
3. **Replay detection keys on the challenge, never on proof bytes,** because a
   Groth16 proof can be re-randomized into different bytes with the same public
   signals.
4. **The holder app, not the SDK, limits disclosure.** A malicious verifier
   controls its own SDK.
5. **Rules, and what they reveal.** A request carries rules: 19 or older, and
   the genders, PIN codes and states it accepts. The circuit outputs gender, PIN
   code and state as values, so a rule on one of them reveals the holder's
   value to the verifier, not only that it passes. The holder app checks the
   rules on the device and reveals nothing when they fail; otherwise it shows
   the person each value it will reveal, and proves only when they go on. For
   gender this reverses the brief's "name and gender proofs are removed", at
   the owner's request ([DECISIONS.md](DECISIONS.md), section 10).
6. **A second credential: DigiLocker's PAN Verification Record.** A request
   lists the credentials it accepts: Aadhaar QRs, PAN records, or both. The
   record is the XML DigiLocker issues after it checks a PAN with the Income Tax
   Department, signed with DigiLocker's own key (RSA with SHA-1 over a SHA-256
   digest of the record). zkID proves it with its own Noir circuit. A PAN record
   has no address, so a request that accepts one cannot have a rule on PIN code
   or state. The age check compares the date of birth with a cutoff, the
   request's day in India 19 years earlier, so "19 or older" means the same for
   both credentials. The nullifier hashes the PAN and the record's `uid`:
   without `uid`, a verifier could find the PAN by trying every PAN number
   ([DECISIONS.md](DECISIONS.md), section 11).

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
| S9 | **Cryptography.** RSA-2048 PKCS#1 v1.5 with SHA-256 (QRs) and SHA-1 (PAN records), Poseidon and Poseidon2, and Groth16 and UltraHonk on BN254 (about 100-bit security) hold. | Standard assumptions. SHA-1 is not collision-resistant; A1.14 shows why that is not enough here. | Everything. |
| S10 | **PAN issuer honesty.** DigiLocker signs a PAN record only with what the Income Tax Department returned for that PAN, in the account of the person it belongs to, and keeps its signing key secret; the Income Tax Department gives a person one PAN. | Not checkable by zkID. | Forgery (G1) or extra accounts (G3), undetectable. |
| S11 | **PAN key authenticity.** The registry's DigiLocker key is DigiLocker's. | The certificate in the owner's DigiLocker records (a PAN record downloaded twice and fetched again, and a driving licence), issued to DS Digital India Corporation by ProDigiSign Sub CA DSC 2022, valid until 11 February 2029. Every one of those records verifies under it. Its chain to India's CCA root was not checked. | A fake key is trusted. |
| S12 | **PAN setup.** At least one participant in Aztec's Ignition ceremony, whose BN254 points UltraHonk uses, destroyed their secret. | The verifier embeds the one point its check uses ([x]₂), and Barretenberg checks it against the SHA-256 it pins. The ceremony itself was not checked here. | PAN proofs can be forged for any statement. |
| S13 | **PAN circuit correctness.** zkID's circuit enforces what circuit-spec section 7 says, and Noir 1.0.0 and Barretenberg (bb.js 5.3.0) compile, prove and verify it as specified. | Tests on synthetic records (circuit-spec, section 7) and on the owner's two real records. Not audited by anyone: the RSA arithmetic and SHA-1 are written by hand, and Noir 1.0.0 was a day old when it was chosen. | Depends on the flaw. |
| S14 | **Stable PAN nullifier material.** A person's PAN and DigiLocker `uid` are the same on every record DigiLocker issues them. | One holder: the same `uid` in a record downloaded twice, nine days apart, and after DigiLocker fetched it again from the Income Tax Department (a new `verifiedOn`, QR and signature). Untested: a second DigiLocker account. | A re-fetch gives another account (G3). |

## 3. Adversaries

From the brief:

| | Adversary | Has | Wants |
|---|---|---|---|
| A1 | Forger | no UIDAI-signed QR or DigiLocker-signed PAN record, or one that does not show 18+ or does not meet the verifier's rules | an accepted proof |
| A2 | Replayer | someone else's proof: captured, screenshotted, or relayed live | acceptance at another verifier, or later |
| A3 | Lender | an adult's QR or PAN record, given to a minor | accounts for the minor |
| A4 | Sybil | their own QR and PAN record | several accounts at one verifier |
| A5 | Linker | records of two or more colluding verifiers | to tell whether two proofs came from one person |
| A6 | Malicious verifier | a request the holder will answer | more than its rules need, such as the value of a field it has no rule on |
| A7 | Tamperer | write access to the QR or PAN record, proof, public signals or request in transit | any accepted change |

## 4. Goals

| Goal | Status under option A | How | Tests |
|---|---|---|---|
| G1 Unforgeability | **Yes**, under S1–S4 for QRs and S9–S13 for PAN records | SHA-256 and RSA over all signed bytes in-circuit (for a PAN record, SHA-256 of the record, then SHA-1 and RSA over DigiLocker's `SignedInfo`); key hash in the registry for that credential; credential time inside the key's window; revealed values checked against the rules; pinned artifacts | T1.1–T1.17, T7.1–T7.3, T7.5–T7.8 |
| G2 Verifier binding | **Yes** for replay; **No** for live relay (A2.5) | `signalHash` is a hash of the request; challenges are single-use and short-lived; a request names the credentials it accepts | T2.1–T2.8, T7.4 |
| G3 Per-verifier uniqueness | **Partly** | per-verifier `nullifierSeed`; for a QR, a nullifier from the photo bytes, the bytes after them and the signed data's length; for a PAN record, from the PAN and DigiLocker's `uid`. Fails on a photo update, on any update that changes a QR's signed data's length, possibly on QRs from other sources, across the two credentials (A4.7), and against anyone who holds the QR or record | T2.5, T3.1, T3.2, T3.4, T4.1–T4.5, T5.1, T5.2, T5.4–T5.6 |
| G4 Freshness | **Yes**, to the hour | the SDK compares the public `timestamp`, or a PAN record's `verifiedHour`, with the request's `maxAge` | T3.3, T3.5, T3.6 |
| G5 Minimal disclosure | **Partly**: the QR's generation hour and the UIDAI key (a PAN record's verification hour and DigiLocker's key) are also revealed, and a rule on gender, PIN code or state reveals that value (decision 5) | the holder app sets only the reveal flags the request's rules need, reveals nothing when the credential breaks them, and proves a PAN record only for a request dated today | T1.10, T5.3, T5.7, T6.1, T6.2, T6.4, T6.5 |
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
age above 18. Rules add a fourth: "never reveals anything else" holds for age
alone; a rule on gender, PIN code or state reveals that value. PAN records
keep these qualifiers and add a fifth: "one account per site" is per
credential, so a person with an Aadhaar QR and a PAN record gets two accounts
at a verifier that accepts both (A4.7).

## 5. Attacks

"Yes" means the mechanism rejects the attack. **No** means it succeeds;
where a test is listed, the test shows it succeeding.

| | Attack | Defended? | Mechanism | Tests |
|---|---|---|---|---|
| A1.1 | Sign a QR or PAN record with your own RSA key | Yes | the circuits accept any key but output its hash; the SDK requires a registry key for that credential | T1.1, T1.12 |
| A1.2 | Change bytes of a genuine QR or PAN record, e.g. the DOB | Yes | SHA-256 and RSA over every signed byte; for a PAN record, SHA-256 of the record, then SHA-1 and RSA over `SignedInfo` | T1.2, T1.13, T7.3 |
| A1.3 | Change the signature, or check it under another key | Yes | RSA check | T1.3, T1.4, T1.13 |
| A1.4 | Get a test key into a production registry | Yes | the production build fails if one is present | T1.5 |
| A1.5 | Sign with an old UIDAI key that leaks after it expires | Yes, once the key has been expired for longer than `maxAge` | the timestamp must be inside the key's window and within `maxAge` | T1.6, T3.3 |
| A1.6 | Sign with UIDAI's current key, or DigiLocker's | **No** | assumptions S1 and S10 | none |
| A1.7 | Swap the verification key, circuit artifacts or registry | Yes | pinned by SHA-256 at build time; the SDK checks the PAN verification key as it loads it | T1.7, T1.17 |
| A1.8 | Forge a proof without a valid witness | Yes, under S3 or S12, and S9 | Groth16 and UltraHonk soundness; the PAN verifier embeds the one setup point its check uses, which Barretenberg checks against its pinned hash | none (assumption) |
| A1.9 | Use a genuine QR or PAN record of someone under 18, or hide the age bit | Yes | when the rules ask for age, `ageAbove18` (a PAN record's `bornBy`) must be 1, which the circuits output only from the 19th birthday | T1.10, T1.15 |
| A1.10 | Exploit unusual signed data: a DOB not in `DD-MM-YYYY`, or non-digits | Partly | fails closed when the DOB is not 10 bytes (the circuit checks the delimiter 11 bytes after its start); digits are not range-checked, so this relies on UIDAI's formatting (S4) | T1.8, T1.9 |
| A1.11 | Pass a verifier's rule on gender, PIN code or state with a credential that breaks it, or by hiding the field | Yes | the circuit outputs the signed value; the SDK compares it with the request's rules, and a field the rules name that the proof hides fails | T1.11, T1.16 |
| A1.12 | Use a validly signed DigiLocker record that is not an active PAN record (another document type, status or issuer), or one whose fields lie outside the bytes the signature covers | Yes | the circuit checks the record's fixed head, each field's exact markup where the prover says it is, and that every field lies in the hashed bytes | T1.14 |
| A1.13 | Prove a PAN record against an earlier date-of-birth cutoff than the request's, so a minor passes | Yes | the SDK requires the cutoff of the request's day | T2.7 |
| A1.14 | Use a SHA-1 collision on DigiLocker's signature | Yes, under S9 | the circuit fixes every byte of `SignedInfo` except the 44-character SHA-256 digest of the record, so a collision would need DigiLocker to sign a `SignedInfo` built for it | none (assumption) |
| A1.15 | Use a key the registry trusts for one credential to sign the other | Yes | registry keys are per credential, and the two circuits hash keys differently | T1.12 |
| A2.1 | Submit a captured proof to another verifier | Yes | different `signalHash` and `nullifierSeed` | T2.1, T2.5, T2.7 |
| A2.2 | Submit it again to the same verifier | Yes | single-use challenge | T2.2, T2.7 |
| A2.3 | Re-randomize the proof and resubmit | Yes | replay detection keys on the challenge | T2.3 |
| A2.4 | Submit after the request expired | Yes | short-lived challenge | T2.4, T2.7 |
| A2.5 | Relay a verifier's live request to a victim, and use the victim's proof for your own session | **No** | the proof is bound to the request, not to who holds the session at the verifier; the holder app shows the verifier's origin, which helps only a careful user | T2.6 |
| A2.6 | Send a proof of a credential the request does not accept, or label a proof as the other credential | Yes | the request lists the credentials it accepts (`DOCUMENT_NOT_ACCEPTED`), the label selects the verification key, and a refusal leaves the request unused | T2.8 |
| A3.1 | Lend an adult's QR or PAN record to a minor: one account per site | **No** | non-goal; preventing it needs biometrics | T3.1 |
| A3.2 | Use the lent QR for a second account at the same site | Yes | same nullifier | T3.2 |
| A3.3 | Use a copy of someone else's QR or PAN record | **No** for recent ones; Yes for ones older than `maxAge` | nothing binds the proof to the holder; freshness rejects old letters and old copies | T3.3, T3.5, T3.6 |
| A3.4 | Update the photo to get another slot | **No** | a new photo gives a new nullifier (Anon Aadhaar audit, High, no fix) | T3.4 |
| A4.1 | Re-download the QR, or re-fetch the PAN record, for a second account | Yes, for the one holder tested (S8, S14) | the same photo and trailing bytes, or the same PAN and `uid`, give the same nullifier | T4.1, T4.4 |
| A4.2 | Prove under a different `nullifierSeed` | Yes | the SDK requires its own seed | T2.5, T2.7 |
| A4.3 | Use QRs from other sources or format versions | Partly | unknown whether a PVC card or the Aadhaar app carries the same bytes; a code with V1's 64 bytes after the photo gives a different nullifier than one with V5's 27, and a V1 code cannot be proved at all; freshness rejects old letters | T4.2, T3.3 |
| A4.4 | Update the photo | **No** | as A3.4 | T3.4 |
| A4.5 | Hold two Aadhaar numbers | **No** | relies on UIDAI's de-duplication (S1) | none |
| A4.6 | Change the length of any signed field, e.g. by an address update, for another slot | **No** | the nullifier covers the SHA-256 padding after the photo, which encodes the signed data's length (found in Phase 6) | T4.3 |
| A4.7 | Use your Aadhaar QR and your PAN record for two accounts at a verifier that accepts both | **No** | the two nullifiers hash different values, and nothing both circuits can see links them; a verifier that needs one account per person accepts one credential | T4.5 |
| A4.8 | Fetch your PAN record into a second DigiLocker account for another slot | **No**, if DigiLocker gives that account another `uid` | the nullifier hashes `uid` (S14; untested) | none |
| A5.1 | Compare nullifiers across sites | Yes, against parties without the QR or record | different seeds; the photo's ~900 bytes, or DigiLocker's 128-bit `uid`, cannot be guessed | T5.1, T5.5 |
| A5.2 | Compute someone's nullifier for every site from their QR or PAN record (anyone with a copy, UIDAI, or DigiLocker) | **No** | the photo and `uid` are not secret from them | T5.2, T5.6 |
| A5.3 | Match the QR's generation hour and key hash across sites, or a PAN record's verification hour | **No** under option A | both are public outputs; a holder who uses a separate fresh QR per site avoids matching hours | T5.3, T5.7 |
| A5.4 | Correlate IP addresses or timing | **No** | out of scope | none |
| A5.5 | Request a proof under another site's id, to learn the user's nullifier there | Yes | the id is the origin the request came from (decision 1) | T5.4 |
| A5.6 | Find the PAN behind a nullifier by trying every PAN number | Yes | the nullifier also hashes `uid`, which a verifier never sees (decision 6) | none |
| A6.1 | Ask the holder app to reveal gender, PIN code or state | Partly | the app reveals a field only when the request has a rule on it, checks the rule on the device first (a QR that breaks it reveals nothing) and shows the person each value before proving; but a rule written to admit everyone, such as all three genders or the PIN prefixes 1 to 9, learns the value of everyone who goes on | T6.1, T6.2, T6.4 |
| A6.2 | Learn the DOB or exact age | Yes | only the 18+ bit is output; for a PAN record, only `bornBy` against the request's cutoff | T6.1 |
| A6.3 | Learn the QR's generation hour and UIDAI key, or a PAN record's verification hour and DigiLocker's key | **No** under option A | always public | T5.3, T5.7 |
| A6.4 | Get the QR or the PAN record itself | Yes, under S7 | the app never sends it | T6.3 |
| A6.5 | Date a request another day, to move a PAN proof's age cutoff and learn the date of birth over several requests | Yes, to within a day | the holder app proves a PAN record only for a request issued in the last day and at most ten minutes ahead of its clock; the SDK sets the cutoff from the request's day | T6.5 |
| A7.1 | Flip a signed byte of the QR or PAN record | Yes | as A1.2 | T1.2, T1.13, T7.3 |
| A7.2 | Change a public signal after proving | Yes | Groth16 or UltraHonk verification | T7.1, T7.7 |
| A7.3 | Change proof bytes | Yes | Groth16 or UltraHonk verification; a re-randomized Groth16 proof stays valid (A2.3) | T7.2, T7.7 |
| A7.4 | Change the request in transit | Yes | fetched over TLS from the verifier's origin; `signalHash` must match the stored request | T7.4 |
| A7.5 | Send malformed QR text or PAN XML | Yes | the parsers fail with a typed error and never fall back | T7.5, T7.8 |
| A7.6 | Give wrong delimiter positions | Yes | the circuit checks each delimiter's position | T7.6 |

## 6. Non-goals and accepted limits

- **Lending and impersonation** (A3.1, A3.3) beyond one account per site per
  QR or PAN record. Preventing them needs biometrics or liveness.
- **One account per person across credentials** (A4.7). A verifier that needs
  it accepts one credential.
- **Full KYC**: address, AML screening, liveness.
- **Name proofs**: removed. Gender, PIN code and state are proved only as a
  verifier's rules, and are then revealed by value (decision 5).
- **Rules as yes or no.** Proving only that a gender, PIN code or state passes a
  rule, without revealing it, needs a new circuit.
- **18-year-olds, and any other cutoff** (accepted by the owner at stop gate 3,
  2026-10-26). Under option A the circuit only outputs "completed age above 18
  on the QR's generation date", which becomes true on the 19th birthday. Holders
  aged 18 cannot prove until then (T1.10). A PAN proof's cutoff matches: 19
  years before the request's day (T1.15).
- **Hiding the QR's generation hour and the UIDAI key**, or a PAN record's
  verification hour and DigiLocker's key, from verifiers (A5.3, A6.3).
- **Revocation.** Secure QR and PAN records have none; freshness is the only
  control.
- **Network anonymity** (A5.4) and **denial of service**.
- **Every holder.** Photos above 924–987 bytes cannot be proved
  (issuer-research, section 7.4), a DOB not in `DD-MM-YYYY` fails (T1.8), as
  does a state name over 31 bytes or a PIN code field that is not 6 bytes
  (`packages/circuit` tests), and
  proving in a desktop browser needs about 5 GB of memory (2.6 GB on one
  thread). The one phone tried ran out of memory with several threads and
  proved in 79 s with one; phones with less memory are untested
  ([circuit-spec.md](circuit-spec.md), section 5). A PAN record's canonical form
  must fit in 3,584 bytes with its fields in the first 1,280, and its layout
  must be the one the circuit reads, which is fitted to one person's records:
  others fail closed. Proving one takes about 1 GB of memory; the owner's phone
  took 13.6 s on 8 threads (circuit-spec, section 7).
- **Novelty.** RSA in a circuit, the circuit itself and the nullifier
  construction are Anon Aadhaar's. zkID contributes the request protocol, the
  seed and freshness policy, the key registry with validity windows, the SDK,
  the holder app, the attack suite, and the PAN circuit, which no one outside
  this project has reviewed.
- **Legal clearance.** Whether a verifier must register with UIDAI is unsettled
  (issuer-research, section 8), as is whether a website may rely on a DigiLocker
  record outside DigiLocker's own sharing flow. This is a research prototype.

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
| T1.11 | 9 | proofs revealing a gender or a PIN code that the request's rules do not accept, and one hiding the state its rules name | `GENDER_NOT_ALLOWED`, `PIN_CODE_NOT_ALLOWED`, `STATE_NOT_ALLOWED`; no account slot taken | passes in `packages/verifier-sdk` tests |
| T1.12 | 10 | PAN proof from a record signed with a fresh key, or with a key the registry trusts only for QRs; a record verified outside its key's validity window | `UNTRUSTED_ISSUER`; `ISSUER_KEY_NOT_VALID` | passes in `packages/verifier-sdk` tests |
| T1.13 | 10 | one byte of a PAN record changed, its signature changed, another key given, a field's position given wrong | the record reader refuses it before proving, and the circuit fails | passes in `packages/pan` tests |
| T1.14 | 10 | validly signed records outside a PAN record's layout: another document type, status or issuer, two different PAN numbers, an unknown gender or `uid`; fields written after the hashed bytes of a short record | the record reader refuses them, and the circuit fails | passes in `packages/pan` tests |
| T1.15 | 10 | PAN records born the day after, on and before the cutoff; the cutoff for requests made in India and elsewhere; a record of someone under 19 | `bornBy` is 1 only on or before the cutoff, which is the request's day in India 19 years earlier; `AGE_NOT_PROVEN`, and no account slot taken | passes in `packages/pan` and `packages/verifier-sdk` tests |
| T1.16 | 10 | PAN proof revealing a gender the request's rules do not accept | `GENDER_NOT_ALLOWED` | passes in `packages/verifier-sdk` tests |
| T1.17 | 10 | one byte changed in the PAN verification key; the pinned key against the pinned program | the SDK refuses to load it; both match their pinned SHA-256 (CI also rebuilds both from the circuit) | passes in `packages/pan` and `packages/verifier-sdk` tests |
| T2.1 | 4 | proof for verifier X sent to verifier Y | `CHALLENGE_MISMATCH` | passes in `packages/verifier-sdk` tests |
| T2.2 | 4 | the same proof sent twice to X | second: `CHALLENGE_REUSED` | passes in `packages/verifier-sdk` tests |
| T2.3 | 4 | re-randomized copy of an accepted proof | `CHALLENGE_REUSED` | passes in `packages/verifier-sdk` tests |
| T2.4 | 4 | proof sent after the request expired | `CHALLENGE_EXPIRED` | passes in `packages/verifier-sdk` tests |
| T2.5 | 4 | proof under another `nullifierSeed` | `NULLIFIER_SEED_MISMATCH` | passes in `packages/verifier-sdk` tests |
| T2.6 | 6 | request from the attacker's session, proved by the victim | accepted (not defended) | passes in `attack-suite` tests |
| T2.7 | 10 | PAN proof sent with another request, twice, after its request expired, with another date-of-birth cutoff, or under another seed | `CHALLENGE_MISMATCH`, `CHALLENGE_REUSED`, `CHALLENGE_EXPIRED`, `CHALLENGE_MISMATCH`, `NULLIFIER_SEED_MISMATCH` | passes in `packages/verifier-sdk` tests |
| T2.8 | 10 | a PAN proof for a request that accepts only QRs, and a QR proof for one that accepts only PAN records; a proof labelled as the other credential, or an unknown one | `DOCUMENT_NOT_ACCEPTED`, and the request stays unused; `BAD_PROOF` | passes in `packages/verifier-sdk` tests |
| T3.1 | 6 | lent QR, first account | accepted (not defended); the QR's owner is then `NULLIFIER_SEEN` | passes in `attack-suite` tests |
| T3.2 | 4 | lent QR, second account at the same site | `NULLIFIER_SEEN` | passes in `packages/verifier-sdk` tests |
| T3.3 | 4 | QR older than `maxAge` | `CREDENTIAL_TOO_OLD` | passes in `packages/verifier-sdk` tests |
| T3.4 | 6 | same identity, new photo bytes | new nullifier; second account accepted (not defended) | passes in `attack-suite` tests |
| T3.5 | 4 | QR exactly `maxAge` old, and one hour older | accepted, then `CREDENTIAL_TOO_OLD` | passes in `packages/verifier-sdk` tests |
| T3.6 | 10 | PAN record that DigiLocker verified longer ago than `maxAge` | `CREDENTIAL_TOO_OLD` | passes in `packages/verifier-sdk` tests |
| T4.1 | 3 | two downloads: same photo and trailing bytes, different generation time | equal nullifiers; second account `NULLIFIER_SEEN` | passes in `packages/circuit` and `packages/verifier-sdk` tests; Phase 1: `check_controls.mjs`; the owner's two real downloads, by byte comparison |
| T4.2 | 6 | the same photo followed by V1's 64 bytes (in a V2-layout code, as in Anon Aadhaar's V2 test data) and by V5's 27; a V1 code | different nullifiers (documents A4.3); the V1 code is refused (`UNSUPPORTED_LAYOUT`) | passes in `attack-suite` tests |
| T4.3 | 6 | same photo and trailing bytes; one field one byte longer, then one changed without changing its length | new nullifier and a second account accepted (documents A4.6); the same nullifier | passes in `attack-suite` tests |
| T4.4 | 10 | the same PAN and `uid` in a record DigiLocker verified again a day later; another person | the same nullifier, so a second account is `NULLIFIER_SEEN`; another `uid` gives another | passes in `packages/pan` and `packages/verifier-sdk` tests; the owner's record and the one DigiLocker verified again nine days later carry the same PAN and `uid`, and the circuit accepts both (run locally, nothing of them committed) |
| T4.5 | 10 | one person's QR and PAN record, at a verifier that accepts both | two accounts (documents A4.7) | passes in `attack-suite` tests |
| T5.1 | 3 | same QR, two verifier ids | different nullifiers | passes in `packages/circuit` tests; Phase 1: `check_controls.mjs` |
| T5.2 | 6 | only a copy of the QR | its nullifier for any verifier id, computed offline, matches the holder's (documents A5.2) | passes in `attack-suite` tests (computed with the circuit's witness generator) |
| T5.3 | 6 | the same QR at two verifiers | identical `timestamp` and `pubkeyHash` (documents A5.3) | passes in `attack-suite` tests |
| T5.4 | 5 | request served from origin B naming verifier A | holder app refuses | passes in `frontend/src/holder` tests (`WRONG_ORIGIN`) |
| T5.5 | 10 | the same PAN record at two verifiers | different nullifiers | passes in `packages/pan` tests and the `apps/demo-rp` end-to-end tests |
| T5.6 | 10 | only a copy of the PAN record | its nullifier for any verifier, computed outside the circuit, matches the holder's (documents A5.2) | passes in `packages/pan` and `attack-suite` tests |
| T5.7 | 10 | the same PAN record at two verifiers | identical `verifiedHour` and `pubkeyHash` (documents A5.3, A6.3) | passes in `attack-suite` tests |
| T6.1 | 5, 9 and 10 | every proof the holder app makes | exactly the nine signals of section 1.1 for a QR, and the eight inputs for a PAN record; `gender`, `pinCode` and `state` are 0 unless the request has a rule on that field | passes in `frontend/src/holder` tests (the circuit inputs), `packages/pan` tests (the circuit's outputs) and the `apps/demo-rp` end-to-end tests (every proof posted, with and without rules) |
| T6.2 | 5 and 9 | request with fields beyond the request format, or with malformed rules | holder app refuses with a typed error | passes in `frontend/src/holder` tests (`UNSUPPORTED_REQUEST`, `BAD_REQUEST`) |
| T6.3 | 5 and 10 | full flow under network capture, with a QR and with a PAN record | no request carries the QR digits, its bytes, the photo, a PAN record's values, digest, signature or QR image, or any field value the rules do not name | passes in the `apps/demo-rp` end-to-end tests: headless Chromium, every request of the pages and the proving workers captured |
| T6.4 | 9 and 10 | QR or PAN record that breaks a request's rule on age or gender (a QR also on PIN code or state); a PAN record that is too old or signed by an untrusted key | holder app refuses before proving, and nothing is sent; for a credential that meets the rules, it shows exactly the values the proof will reveal | passes in `frontend/src/holder` tests and the `apps/demo-rp` hosted end-to-end test |
| T6.5 | 10 | request dated more than a day before, or more than ten minutes after, the holder's clock, for a PAN record | holder app refuses before proving (`REQUEST_NOT_CURRENT`) | passes in `frontend/src/holder` tests |
| T7.1 | 3 and 4 | each public signal changed after proving | Groth16 verification fails (Phase 3); `BAD_PROOF`, except `nullifierSeed` and `signalHash`, which the SDK checks first: `NULLIFIER_SEED_MISMATCH`, `CHALLENGE_MISMATCH` (Phase 4) | passes in `packages/circuit` and `packages/verifier-sdk` tests |
| T7.2 | 4 | each proof element changed | `BAD_PROOF` | passes in `packages/verifier-sdk` tests |
| T7.3 | 5 | every signed byte of a synthetic V5 QR flipped, one at a time, in the holder app's parser | signature check fails before proving | passes in `packages/secure-qr` tests (`web.mjs`, the holder app's parser) |
| T7.4 | 4 | `verifierId`, challenge, `maxAge`, expiry or rules changed after proving | `CHALLENGE_MISMATCH` | passes in `packages/verifier-sdk` tests |
| T7.5 | 5 | malformed QR text: not decimal, bad compression, unknown version, truncated | typed parser error | passes in `packages/secure-qr` tests, for the Node parser and the holder app's (`web.mjs`) |
| T7.6 | 3 | delimiter positions shifted | witness generation fails | passes in `packages/circuit` tests; Phase 1: `check_controls.mjs` (DOB hint) |
| T7.7 | 10 | one byte of a PAN proof, or one of its public inputs, changed; malformed proofs and inputs | Barretenberg rejects it; `BAD_PROOF`, and the request stays unused | passes in `packages/pan` and `packages/verifier-sdk` tests |
| T7.8 | 10 | malformed PAN XML: not XML, a DOCTYPE, namespaces, not a PAN record | typed reader error before proving | passes in `packages/pan` tests |

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
- How does UIDAI write state names, such as Delhi or Dadra and Nagar Haveli and
  Daman and Diu? A state rule must match its spelling, and a name over 31
  bytes cannot be proved at all.
- Does a second DigiLocker account for the same person get another `uid`, and
  can one person have two? (A4.8, S14)
- Do other people's PAN records have the owner's layout? Only one person's
  records were seen; a different layout fails closed. (circuit-spec, section 7)
- Does DigiLocker's certificate chain to India's CCA root, and how will
  verifiers learn DigiLocker's next key before February 2029? (S11)
- Will anyone review the PAN circuit, and Noir and Barretenberg as used here?
  (S13)

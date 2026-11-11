# PAN prototype

Can a phone prove claims from a DigiLocker **PAN Verification Record** without
showing it? This prototype answers with a working circuit, tests, and timings.
It is not wired into the SDK, the holder app or the demo, and its proving key
has no trusted setup: whoever ran `build.mjs` could forge proofs with it.

## What the record is

DigiLocker offers the record as PDF, XML and JSON. The XML is signed by
DigiLocker (XMLDSig, enveloped): SHA-256 of the record's exclusive-canonical
form is the `DigestValue` in `SignedInfo`, and `SignedInfo` is signed with
**RSA-SHA1** under DigiLocker's own document-signing key ("DS DIGITAL INDIA
CORPORATION", RSA-2048, issued by ProDigiSign Sub CA DSC 2022, valid until
February 2029). The signature is DigiLocker's, not the Income Tax
Department's. The JSON carries the same kind of signature over an XML it does
not include; it can be rebuilt (checked on the owner's records), but the XML is
simpler. One record is 3,186 signed bytes; its QR image is most of them.

The record has the full date of birth, gender, PAN number, a 32-hex `uid`, and
`verifiedOn`, when DigiLocker checked the PAN with the Income Tax Department.
Its address fields are empty.

## What the circuit proves

`circuits/pan-verifier.circom` (with `sha1.circom` and the generated
`constants.circom`) takes the canonical record and the signature, and checks:

- SHA-256 of the record, as base64, inside DigiLocker's exact `SignedInfo`;
  SHA-1 of that `SignedInfo`, from the state after its constant first seven
  blocks; RSA PKCS#1 v1.5 with SHA-1 under the key;
- the record's fixed head: a PAN record (`type="PANCR"`), issued through
  DigiLocker by the Income Tax Department, `status="A"`;
- the date of birth, gender, `uid` and `<PAN>` attributes where the prover's
  hints point, each matched by its exact markup, the two PAN numbers equal,
  all inside the hashed bytes. (Until 2026-11-11 the circuit did not check
  that last part: for a signed record shorter than 1,280 bytes, a prover could
  have written the attributes after its end, where the signature does not
  reach. Real records are about 3 KB.)

Public outputs: the key's hash (as Anon Aadhaar computes it), a per-verifier
nullifier `Poseidon(seed, PAN, uid)`, the hour DigiLocker verified the PAN
(`YYYYMMDDHH`, IST), whether the holder was born on or before a date the
verifier chose (`dobCutoff`, so any age, not only 19+), and the gender if the
holder reveals it. Public inputs: `dobCutoff`, the nullifier seed and the
signal hash, as in zkID's request protocol.

## Results

Measured on 2026-10-27 in a 4-core Intel Xeon container (2.3 GHz, 16 GB),
snarkjs 0.7.6, next to Anon Aadhaar's circuit as measured on the same kind of
machine (`spike/circuit-cost/results`, docs/circuit-spec.md section 5).

| | PAN record (this circuit) | Aadhaar QR (Anon Aadhaar) |
|---|---|---|
| Constraints | 1,989,686 (the timings below were made with 26 fewer) | 1,040,218 |
| Proving key | 1,133 MB (536 MB gzipped) | 612 MB (296 MB in gzip parts) |
| Witness wasm | 11.7 MB | 10.5 MB |
| Node, 4 threads | 120 s to prove (7 s witness), 6.7 GB peak | 34 s, 3.8 GB |
| Node, 1 thread | 105 s (4 s witness), 3.5 GB | |
| Chromium, 4 threads | 74 s (78 s in a second run), 9.0 GB for the browser | 52 s, 4.8 GB |
| Chromium, 1 thread | 118 s (127 s), 4.7 GB | about 80 s, 2.6 GB |
| Setup (`build.mjs`, no ceremony) | 18 minutes, about 11 GB | |

Checked:

- **Synthetic records** (`npm test`, 9 tests): the outputs equal what
  `record.mjs` computes outside the circuit; the date-of-birth cutoff holds to
  the day; the nullifier is stable for a PAN and uid and differs per verifier
  and per person; one changed byte anywhere in the record, a changed signature,
  another key, or a wrong hint fails; validly signed records outside the
  layout (another document type, another status, two different PAN numbers,
  another organization) fail; and attributes written after a short record's
  hashed bytes fail.
- **The owner's real record**, and the same record fetched again nine days
  later (`PAN_XML=...`, run locally, nothing printed): each read, checked, and
  accepted by the circuit, with the outputs it should give.

**On a phone.** The owner's phone (8 cores, at least 8 GB, Android 16, Chrome
156) proved a synthetic record on one thread in 213 s, after 6 s for the
witness and 72 s to download and unpack the key, using the test page in
bhargava-sarma/zkID-pan-bench. The same phone proves an Aadhaar QR in 79 s on
one thread, so there a PAN proof takes about 2.7 times as long, more than the
1.5 times measured above. It needs about 4.7 GB rather than 2.6 GB, so phones
with less memory probably cannot make one. Several threads need 9 GB, too much
for any phone. The first proof also downloads 536 MB rather than 296 MB.

## Open questions before building it for real

1. **Is `uid` stable?** So far, yes. It was the same in two downloads 5
   seconds apart; in a download nine days later, which was DigiLocker's stored
   copy byte for byte; and after the owner had DigiLocker fetch the record
   again from the Income Tax Department, which gave a new `verifiedOn`, QR
   image and signature. The circuit accepted that record too, with the same
   nullifier. It differs from the `uid` on the same person's driving licence.
   Untested: whether a second DigiLocker account for the same person would
   get another `uid`, and so another nullifier.
2. **The nullifier without `uid` would leak the PAN.** PAN numbers of
   individuals have about 4.6 billion values, fewer when the surname's
   initial is known, so a verifier could brute-force `Poseidon(seed, PAN)` in
   hours. `uid`, which verifiers never see, is what prevents that.
3. **One record seen.** The fixed head, the 3,584-byte limit and the
   1,280-byte field window are fitted to the owner's record. A long name, a
   larger QR or a non-empty `email` before `gender` is handled; other changes
   fail closed. More records, from other people, would show the variation.
4. **SHA-1.** DigiLocker's signature hashes `SignedInfo` with SHA-1. A
   collision there would need DigiLocker to sign a crafted `SignedInfo`, whose
   only free part is the SHA-256 digest, so the practical risk is low; the
   circuit also depends on `SignedInfo`'s exact whitespace.
5. **Key rotation and trust.** The verifier pins DigiLocker's key hash, as the
   issuer registry pins UIDAI's, and must add the next key before February 2029.
6. **A verifier-chosen cutoff leaks over many proofs.** Each proof shows one
   bit about the date of birth; a verifier asking repeatedly with different
   dates narrows it down. The holder app would allow only "N years before
   today" for a few values of N.
7. **Setup.** Production needs a phase-2 ceremony for this circuit, or a proof
   system without one (Noir with UltraHonk), which could also be much faster
   on SHA-256; installing its toolchain was blocked here.
8. **Legal.** Whether a website may rely on DigiLocker records outside
   DigiLocker's own sharing flow is unsettled, as for Secure QR.

## Run it

```bash
cd spike/pan && npm install
npm test                                     # SHA-1 and record checks; witness tests skip until built
node --max-old-space-size=12000 build.mjs    # circom (2 min), Hermez 2^21 ptau (2.4 GB), dev setup (about 20 min, 12 GB)
npm test                                     # everything, on synthetic records signed by a TEST key
PAN_XML=<a real record, outside git> npm test   # also that record; nothing of it is printed
node --max-old-space-size=12000 bench.mjs [--single]
node browser-bench.mjs [--single]            # headless Chromium (apps/demo-rp's Playwright)
```

Real records stay out of git (`spike/pan/local/` is ignored). `synthetic.mjs`
makes records in DigiLocker's layout and serialization, with the name
"SYNTHETIC TEST PERSON", signed by an ephemeral TEST key under a self-signed
TEST certificate.

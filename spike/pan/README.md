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
  hints point, each matched by its exact markup, the two PAN numbers equal.

Public outputs: the key's hash (as Anon Aadhaar computes it), a per-verifier
nullifier `Poseidon(seed, PAN, uid)`, the hour DigiLocker verified the PAN
(`YYYYMMDDHH`, IST), whether the holder was born on or before a date the
verifier chose (`dobCutoff`, so any age, not only 19+), and the gender if the
holder reveals it. Public inputs: `dobCutoff`, the nullifier seed and the
signal hash, as in zkID's request protocol.

## Results

RESULTS

## Open questions before building it for real

1. **Is `uid` stable?** It was the same in two downloads 5 seconds apart, and
   differs from the `uid` on the same person's driving licence. If it changes
   over time, the nullifier does too, and so does "one account per person". A
   download days later would tell.
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

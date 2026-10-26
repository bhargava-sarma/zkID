# Decisions

What the v2 overhaul cut or chose, and why. v1 is preserved at tag
`v1-mock-issuer-demo`.

## 1. The trust anchor: UIDAI's signature, not our own

v1 read a photo of an Aadhaar card with OCR and signed what it read with a key
of its own. That signature only said "our server read a photo": an edited photo
gave a valid credential, and the private key was committed to git, so anyone
could sign anything ([SECURITY_NOTES.md](../SECURITY_NOTES.md), sections 1 and
4).

v2 proves UIDAI's own RSA signature on the Aadhaar Secure QR, which every
e-Aadhaar, Aadhaar letter and PVC card carries
([issuer-research.md](issuer-research.md), sections 2–4). Cut with it: OCR
(Tesseract), image preprocessing, the server-side signer and prover, and the
Supabase database.

UIDAI's newer Aadhaar Verifiable Credentials were considered and rejected: UIDAI
releases them only to registered verifiers, so a third-party app cannot use them
(issuer-research, section 2.3).

## 2. The circuit: Anon Aadhaar's, unchanged

At stop gate 1 (2026-10-26) the owner chose option A: Anon Aadhaar's published
circuit and proving key, unchanged, over writing a new circuit (option B). Its
key comes from a ceremony with 105 contributions and a beacon, which
`snarkjs zkey verify` confirms against the circuit rebuilt from source
([circuit-spec.md](circuit-spec.md), section 1); a new circuit would have needed
a new trusted setup and an audit.

The costs, all documented: the circuit proves "19 or older" rather than "18 or
older" (accepted at stop gate 3), it outputs the QR's generation hour and the
UIDAI key hash publicly, and its nullifier construction is fixed, including its
dependence on the photo and on the signed data's length
([THREAT_MODEL.md](THREAT_MODEL.md), A3.4, A4.6, A5.3).

## 3. Name and gender proofs: removed

v1's name and gender proofs disclosed what they claimed: the gender in clear, the
name as a hash anyone can test against a list of names. v2 proves one thing, "19
or older". The circuit can also reveal gender, PIN code and state; the holder app
never does, and refuses requests that ask (THREAT_MODEL, A6.1).

## 4. No server and no database

The holder app reads the QR and proves in the browser; the verifier SDK runs at
the website; nothing stores an identity attribute. The end-to-end test checks
that no request carries any part of the QR (THREAT_MODEL, T6.3).

## 5. Freshness in the SDK, not the circuit

The brief put the freshness cutoff inside the circuit. Anon Aadhaar's circuit
outputs the QR's generation time instead, so the SDK compares it with the
request's maximum age. It works to the hour, and the public time is what costs
minimal disclosure (THREAT_MODEL, G4 and G5).

## 6. The request protocol

Four decisions from the threat model, accepted by the owner on 2026-10-26
(THREAT_MODEL, section 1.2): the verifier id is the website's HTTPS origin, and
the holder app fetches the request from that origin and posts the proof back to
it; `AGE_NOT_PROVEN` replaces the brief's `CUTOFF_TOO_LATE`, and
`ISSUER_KEY_NOT_VALID` and `NULLIFIER_SEED_MISMATCH` were added; replay
detection keys on the request's challenge, never on proof bytes, because a
Groth16 proof can be re-randomized; and the holder app, not the SDK, limits what
is disclosed.

## 7. No on-chain module (Phase 7)

The brief asks whether an on-chain consumed-nullifier set or issuer registry
gives something the SDK cannot: shared state across verifiers, or composability
with a contract action. It does not, for zkID's purpose:

- **Shared nullifiers.** A nullifier is per verifier by design. A set shared by
  several verifiers would need one seed for all of them, which gives a person the
  same nullifier at every one: the cross-site linking zkID exists to prevent
  (THREAT_MODEL, G3). A per-verifier set on a chain stores what the verifier's
  own database stores, and also publishes when each account was made.
- **Issuer registry.** UIDAI has four Secure QR keys, replaced every few years.
  The SDK pins them, and a build fails if a test or compromised key is present.
  An on-chain registry adds an owner who can add issuers, which is how v1 failed:
  its owner-managed list trusted a key whose private half is public
  (SECURITY_NOTES, section 2). It would also make every verifier depend on an RPC
  endpoint.
- **Contract actions.** Gating a contract call on a proof is a real use, but a
  different protocol: the verifier is a contract, challenges come from the chain
  or from the caller's address, and freshness uses block time. It would need its
  own threat model, and Anon Aadhaar already publishes a Solidity verifier
  (`AnonAadhaar.sol`) and a nullifier-gated example (`AnonAadhaarVote.sol`) for
  it. zkID's question is proving age to websites.

So zkID has no chain code. Removed: the v1 contracts with their deploy scripts
and tests (`backend/hardhat-deploy`), the frontend's contract client, address
list and `ethers`, the read-only audit scripts for the v1 deployment
(`tools/v1-audit`, kept at commit `2dfc7ce`; their results are in
SECURITY_NOTES), and the README's Sepolia section. Nothing was deployed, and no
v1 contract is reused. v1's Sepolia contracts stay deployed and retired; their
addresses and the forgery they accept are in SECURITY_NOTES, section 2.

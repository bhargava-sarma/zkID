# Credential Age Proof (composed circuit)

Proves, in a single circuit, that an issuer signed a payload **and** that the date of birth
inside those signed bytes clears an age threshold. This is the trustless attestation the
legacy pipeline lacks — the date is not an input, it is extracted in-circuit from the very
bytes the RSA signature covers, so a proof cannot assert an age different from the signed one.

## ⚠️ This directory is load-bearing, not just an experiment

`backend/composedproof.js` **requires `gen_input.js` from here at runtime**, and reads the
proving artifacts from this directory by path. It is still under `experiments/` because the
128 MB proving key has not been moved into `backend/` yet — a deliberate deferral, not an
oversight.

Consequences:

- `gen_input.js`, `circuits/`, and this README are **tracked**. Do not let them fall back
  under the `.gitignore` deny-by-default ladder; a fresh clone without `gen_input.js` cannot
  boot the backend at all (`Cannot find module`).
- The **artifacts are not tracked** and a fresh clone will not have them. That case is handled
  gracefully: `POST /api/signed-proof` returns `PROVING_UNAVAILABLE` (HTTP 500,
  `reason: artifact_missing`) rather than crashing. Everything else in the backend still works.

## What the circuit does

`CredentialAgeProof(119)` composes four stages:

1. SHA-256 over the 119-byte space-padded signed payload (2 blocks).
2. `RSAVerifier65537(121, 17)` — verifies the issuer's RSA-2048 PKCS#1 v1.5 signature over
   that digest. The SHA→RSA glue packs the digest into 121-bit limbs, LSB-first.
3. A uniqueness scan locating `"dob":"` exactly once, then one `VarShiftLeft` pass to bring
   the 10-byte date to a constant offset.
4. Digit range checks, `year*10000 + month*100 + day` encoding, and `LessEqThan(32)` against a
   public threshold date — **asserted**, so a witness exists only for someone old enough.

Private: `msg`, `signature`, `dobIndex`. Public: `modulus`, `thresholdDate`. A verifier learns
which issuer signed and that the subject qualifies — not the name, ID number, gender, or date
of birth.

**Scope:** fixed-key, fixed-width extraction from a canonically serialized payload — *not* a
general JSON parser. The key must be exactly `"dob":"` and the value exactly 10 bytes. Field
*order* is not assumed. Calendar correctness is not validated: `1990-13-45` passes every guard.

## Measured

| | |
|---|---|
| Constraints | 256,574 |
| ptau | pot19 (pot18 fits with 2.1% headroom) |
| zkey | 128 MB |
| Witness generation | ~0.8 s |
| Proving | ~3.6 s standalone, ~4.3 s through the endpoint |
| Verification | ~7 ms |

Negative controls all reject at witness generation: tampered signature, tampered date bytes
with the signature left alone (the binding test), and tampered modulus. A validly-signed minor
fails on the age assertion specifically, not the signature.

## Rebuilding the artifacts

Needed after a fresh clone, or after re-signing changes the circuit's expectations.

```bash
cd experiments/credential-age-proof
NM=../rsa-baseline/node_modules          # circom deps live there; run that setup first

circom circuits/credential_age_proof.circom --r1cs --wasm --sym -l $NM -o .
snarkjs r1cs info credential_age_proof.r1cs        # expect 256,574 constraints

curl -sL -o powersOfTau28_hez_final_19.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_19.ptau

snarkjs groth16 setup credential_age_proof.r1cs powersOfTau28_hez_final_19.ptau cap_0000.zkey
snarkjs zkey contribute cap_0000.zkey cap_final.zkey -n="composed v1" -e="not-for-production"
snarkjs zkey export verificationkey cap_final.zkey verification_key.json
```

The entropy above is a fixed throwaway string. This is **not** a trustworthy ceremony and the
resulting zkey must never be used for anything real.

## Standalone use

`gen_input.js` also runs as a CLI against `mock-issuer/circuit_inputs.json`, with `--tamper=`
modes for the negative controls. The backend imports its `buildCircuitInput` instead, building
inputs in memory for a credential signed at request time.

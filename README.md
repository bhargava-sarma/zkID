# zkkyc_demo

Privacy-preserving KYC using zero-knowledge proofs. A user uploads an Aadhaar card image; the system extracts the identity fields and proves facts about them (age ≥ 18, name match, gender match) **without revealing the underlying values**.

Proofs are Groth16 (circom + snarkjs), verified locally and, for age and name, on-chain on the Polygon Amoy testnet.

## Two proof paths

| | Legacy path | Issuer-signed path |
|---|---|---|
| Endpoints | `/api/upload`, `/api/generate-*-proof` | `/api/signed-proof` |
| The proof says | the value **this server stored** satisfies the predicate | **an issuer signed** a payload, and the DOB **inside those signed bytes** satisfies the predicate |
| Trust root | the server | the issuer's RSA public key |
| Circuit | `AgeVerification`, 37 constraints | `CredentialAgeProof(119)`, 256,574 constraints |
| Proving time | ~0.2 s | ~4 s |
| Storage | derived values in Supabase | none |

The legacy path is circular: the server attests to its own arithmetic. The signed path breaks that circle. The DOB is extracted in-circuit from the signed bytes, so a proof cannot claim a date different from the one the issuer signed.

## Repository structure

```
backend/                    Express API
  ocr.js                    Tesseract extraction + field regexes
  preprocessing.js          Date encoding, SHA-256 hashing, gender encoding
  db.js                     Supabase client (derived values only)
  proofgen.js               Legacy Age/Name/Gender proofs
  signedcredential.js       OCR fields -> canonical payload -> RSA signature
  composedproof.js          Composed-circuit proof (RSA verify + DOB extraction + age check)
  circuits/                 Legacy circuits and build artifacts (committed)
  hardhat-deploy/           Verifier contracts and deploy scripts
frontend/                   React + Vite four-step UI
mock-issuer/                RSA-2048 issuer: keygen, signing, 12-check verifier
experiments/
  credential-age-proof/     Composed circuit + input builder (used by the backend at runtime)
```

## Circuits

| Circuit | Private input | Public input | Proves |
|---|---|---|---|
| `AgeVerification` | `dobEncoded` | `thresholdDate` | DOB ≤ threshold |
| `NameVerification` | `nameHash` | `claimedNameHash` | stored name hash = claim |
| `GenderVerification` | `genderCode` | `claimedGender` | stored gender = claim |
| `CredentialAgeProof(119)` | `msg`, `signature`, `dobIndex` | `modulus`, `thresholdDate` | issuer signed `msg`, and its DOB ≤ threshold |

Dates are encoded as `year*10000 + month*100 + day` (`1998-04-12` → `19980412`), so integer order is date order and there is no leap-year arithmetic.

## Setup

Prerequisites: Node.js ≥ 18. Rebuilding circuits also needs `circom` 2.x and `snarkjs`.

```bash
cp .env.example .env    # SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
```

The backend reads `.env` from the **repository root**. It needs the **service role** key: RLS is enabled on `users` with no policies, so the anon key is refused. The key never leaves the server, because the frontend talks only to the backend.

Supabase table:

```sql
create table public.users (
  id           uuid primary key default gen_random_uuid(),
  name         text,
  dob_encoded  integer,
  aadhaar_hash text,
  name_hash    text,
  gender_code  integer,
  created_at   timestamptz default now()
);
alter table public.users enable row level security;
```

Run:

```bash
cd backend  && npm install && npm run dev    # http://localhost:3001
cd frontend && npm install && npm run dev    # http://localhost:5173 (proxies /api to 3001)
```

### Composed-circuit artifacts

The legacy circuit artifacts are committed. The composed circuit's are not (the zkey is 128 MB). Until you build them, `/api/signed-proof` returns `PROVING_UNAVAILABLE`, and everything else still works.

```bash
cd experiments/credential-age-proof
npm install
circom circuits/credential_age_proof.circom --r1cs --wasm --sym -l node_modules -o .
curl -sL -o powersOfTau28_hez_final_19.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_19.ptau
snarkjs groth16 setup credential_age_proof.r1cs powersOfTau28_hez_final_19.ptau cap_0000.zkey
snarkjs zkey contribute cap_0000.zkey cap_final.zkey -n="composed v1" -e="not-for-production"
snarkjs zkey export verificationkey cap_final.zkey verification_key.json
rm cap_0000.zkey
```

The contribution uses fixed entropy. This is not a trustworthy ceremony.

### Rebuilding legacy circuits

```bash
cd backend/circuits && bash setup_circuit.sh
```

This generates **new** keys, which will no longer match the deployed verifier contracts. Redeploy afterwards.

## Mock issuer

```bash
cd mock-issuer
node sign_credential.js     # payload.json -> signed_credential.json + circuit_inputs.json
node verify_credential.js   # 12 independent checks, including 2 tamper controls
```

The key pair is throwaway mock material and is committed deliberately. `generate_keypair.js --force` rotates it, which invalidates every signed credential.

Signed byte format:
- Exactly four string fields (`dob`, `gender`, `id_number`, `name`), printable ASCII, no `"` or `\`
- Keys sorted, `JSON.stringify` with no whitespace
- Right-padded with spaces to **119 bytes**, the largest size that keeps SHA-256 at two blocks
- RSASSA-PKCS1-v1_5 over SHA-256 with RSA-2048, e = 65537
- Modulus and signature split into 17 × 121-bit limbs, least significant first, for `RSAVerifier65537(121, 17)`

Negative controls against the composed circuit:

```bash
cd experiments/credential-age-proof
W="node credential_age_proof_js/generate_witness.js credential_age_proof_js/credential_age_proof.wasm"
node gen_input.js && $W input.json w.wtns                                   # accepted
node gen_input.js --tamper=date && $W input_tampered_date.json w.wtns       # rejected: RSA check
node gen_input.js --threshold 19000101 --out f.json && $W f.json w.wtns     # rejected: age check
```

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/upload` | multipart `aadhaar` image → OCR → preprocess → store |
| `POST /api/demo` | `{scenario: valid \| underage \| ocr_fail}`, a canned version of `/api/upload` |
| `POST /api/generate-proof` | `{userId}` → age proof |
| `POST /api/generate-name-proof` | `{userId, claimedName}` → name proof |
| `POST /api/generate-gender-proof` | `{userId, claimedGender}` → gender proof |
| `POST /api/signed-proof` | multipart `image`, or `{scenario}` → issuer-signed composed proof |

`/api/signed-proof` scenarios: `valid`, `underage`, `ocr_fail`, `malformed_name`, `gender_missing`, `dob_garbled`, `long_name`.

```bash
curl -s -X POST localhost:3001/api/signed-proof \
  -H 'Content-Type: application/json' -d '{"scenario":"valid"}'
```

Failures return a machine-readable `code`, `reason` and `stages[]`:

| `code` | HTTP | `retryable` | Meaning |
|---|---|---|---|
| `CREDENTIAL_UNPROCESSABLE` | 422 | `true` | OCR output can't form a valid credential. Retake the photo |
| `AGE_REQUIREMENT_NOT_MET` | 422 | `false` | Valid credential, but the subject is under age |
| `PROVING_UNAVAILABLE` | 500 | `false` | Missing artifacts or keys (an operator problem) |

Gender is never defaulted: a guessed value would be signed as issuer-attested fact.

## On-chain verification

Verifiers on Polygon Amoy (chain ID 80002), configured in `frontend/src/contracts/contractConfig.js`:

- `AgeVerifier`: `0xa5075F2E83167C3c7fE5c3C3F1Fc5FCF1d378232`
- `NameVerifier`: `0x23715a3216ACdF715a75463939A342b844dd01eE`
- Retired `AgeVerifier` (old days-since-epoch circuit, 2 public signals): `0xAcA82391AA33bA2070df3e601e71c2b012752d72`

Verification is a read-only `view` call, so it needs no wallet and no gas. The frontend RPC can be overridden with `VITE_AMOY_RPC_URL` in `frontend/.env.local`, and it must be CORS-enabled.

To redeploy the age verifier, copy `backend/hardhat-deploy/.env.example` to `.env.hardhat`, set `PRIVATE_KEY`, then:

```bash
cd backend/hardhat-deploy && npm run deploy:age
```

`npm run deploy:all` redeploys all three and mints new addresses for unchanged circuits.

## Privacy

- Uploaded images are held in memory only and never written to disk.
- Raw ID numbers are never stored, never logged in full (only `********9012`), and never returned to the client. On `/api/signed-proof` the raw ID exists only in memory, inside the signed bytes, which are a private circuit input.
- Secrets live in `.env` and `backend/hardhat-deploy/.env.hardhat`. Both are gitignored.

## Known limitations

- The issuer is a mock. Swapping in a real issuer's modulus leaves the circuit unchanged.
- The frontend drives the legacy endpoints only. `/api/signed-proof` is exercised via `curl`.
- The composed circuit has no on-chain verifier, and `GenderVerifier` is not deployed.
- Calendar validity is not checked: `1990-13-45` passes every guard.
- OCR is regex-based against one Aadhaar layout and is sensitive to image quality.
- Name and gender proofs compare against a hash the server computed. They demonstrate the ZK pattern, not trustless attestation.
- Composed proofs take ~4 s, so a production version would need client-side proving.

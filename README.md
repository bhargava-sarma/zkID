# zkkyc_demo

Privacy-preserving Know-Your-Customer (KYC) demo using zero-knowledge proofs. A user uploads an Aadhaar card image; the system extracts the identity fields, irreversibly transforms them, and can then prove facts about that identity — age over 18, name match, gender match — **without revealing the underlying values**.

Proofs are Groth16 (circom + snarkjs), verified both locally and on-chain against verifier contracts deployed to the Polygon Amoy testnet.

---

## 1) What it does

- Capture a KYC document image (held in memory, never written to disk)
- Extract text via OCR (tesseract.js)
- Transform to circuit-friendly values: DOB → days since Unix epoch, name and Aadhaar number → SHA-256 hashes, gender → integer code
- Store **only the derived values** in Supabase; the raw Aadhaar number is discarded
- Generate and verify ZK proofs over those values
- Optionally re-verify the age and name proofs on-chain

## 2) Repository structure

```
backend/                  Express API: upload, OCR, preprocessing, proof generation
  ocr.js                  Tesseract extraction + field regexes
  preprocessing.js        DOB→days, SHA-256 hashing, gender encoding
  db.js                   Supabase client (stores derived values only)
  proofgen.js             snarkjs Groth16 prove + verify
  circuits/               circom 2.0 circuits and build artifacts
  hardhat-deploy/         Solidity verifier contracts and deploy script
frontend/                 React + Vite four-step UI
  src/components/         UploadStep, PreprocessStep, StorageStep, ProofStep
  src/contracts/          On-chain verification via ethers
```

## 3) The circuits

| Circuit | Private input | Public input | Proves |
|---|---|---|---|
| `AgeVerification` | `dobEncoded` | `thresholdDate` | Age ≥ threshold, without revealing DOB |
| `NameVerification` | `nameHash` | `claimedNameHash` | Stored name matches a claim, without revealing the name |
| `GenderVerification` | `genderCode` | `claimedGender` | Stored gender matches a claim, without revealing it |

## 4) Setup

Prerequisites: Node.js LTS ≥ 18, npm. For rebuilding circuits you also need `circom` (2.x) and `snarkjs` installed globally.

**Environment** — the backend reads `.env` from the **repository root** (not from `backend/`):

```bash
cp .env.example .env      # then fill in SUPABASE_URL and SUPABASE_ANON_KEY
```

The Supabase project needs a `users` table with columns: `id`, `name`, `dob_encoded`, `aadhaar_hash`, `name_hash`, `gender_code`, `created_at`.

`dob_encoded` stores the date of birth as `year*10000 + month*100 + day` (so `1998-04-12` is `19980412`).
It replaced `dob_days`, which held days since the Unix epoch — see *Migrating from `dob_days`* below.

**Row Level Security.** RLS is enabled on `users` with no policies, so the anon key is refused on
insert (`code 42501`). The backend therefore uses the **service role key**
(`SUPABASE_SERVICE_ROLE_KEY`), which bypasses RLS. That is safe only because the key never leaves
the server — the frontend has no Supabase client and talks only to the backend. Do not reuse this
key in any browser-side code.

### Migrating from `dob_days`

The age circuit changed from days-since-epoch to encoded dates, so the column changed with it.
**Run this yourself in the Supabase SQL editor** — the backend will fail with
`Could not find the 'dob_encoded' column of 'users' in the schema cache` until you do.

This adds a new column and backfills it rather than renaming the old one. Renaming would be
actively dangerous: the stored values are day counts, and reinterpreting `7305` as `YYYYMMDD`
yields nonsense that still looks like a valid integer. Additive migration also keeps `dob_days`
around as a rollback path until you are confident.

```sql
BEGIN;

-- 1. Add the new column. Max value 99991231 fits comfortably in int4.
ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS dob_encoded integer;

-- 2. Backfill: days-since-epoch -> YYYYMMDD.
UPDATE public.users
SET dob_encoded =
        EXTRACT(YEAR  FROM (DATE '1970-01-01' + dob_days))::int * 10000
      + EXTRACT(MONTH FROM (DATE '1970-01-01' + dob_days))::int * 100
      + EXTRACT(DAY   FROM (DATE '1970-01-01' + dob_days))::int
WHERE dob_days IS NOT NULL
  AND dob_encoded IS NULL;

-- 3. Check before committing: with_old and with_new should match.
SELECT count(*) AS total,
       count(dob_days)    AS with_old,
       count(dob_encoded) AS with_new
FROM public.users;

COMMIT;
```

Once the app is confirmed working, drop the old column separately:

```sql
ALTER TABLE public.users DROP COLUMN dob_days;
```

Optionally tighten afterwards, once every row is populated:

```sql
ALTER TABLE public.users
  ALTER COLUMN dob_encoded SET NOT NULL,
  ADD CONSTRAINT dob_encoded_range CHECK (dob_encoded BETWEEN 19000101 AND 99991231);
```

**Backend:**

```bash
cd backend
npm install
npm run dev               # http://localhost:3001
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev               # http://localhost:5173
```

The Vite dev server proxies `/api` to `localhost:3001`, so run the backend first.

**Circuits** — prebuilt artifacts (`.wasm`, `.zkey`, vkeys) are committed, so the app runs without this step:

```bash
cd backend/circuits
bash setup_circuit.sh     # downloads the ptau file, compiles, runs Groth16 setup
```

> Re-running the setup produces **new** proving/verifying keys, which will no longer match the already-deployed verifier contracts. Redeploy from `backend/hardhat-deploy/` if you rebuild.

## 5) On-chain verification

Verifier contracts on Polygon Amoy (chain ID 80002), addresses in `frontend/src/contracts/contractConfig.js`:

- `AgeVerifier` — `0xa5075F2E83167C3c7fE5c3C3F1Fc5FCF1d378232` (takes **1** public signal)
  - Retired: `0xAcA82391AA33bA2070df3e601e71c2b012752d72` — the days-since-epoch verifier, which
    took **2** public signals. Still on-chain and still valid for proofs built against the old
    circuit, but its ABI is not interchangeable with the current one.
- `NameVerifier` — `0x23715a3216ACdF715a75463939A342b844dd01eE`

Verification is a read-only `view` call, so no wallet or gas is needed. To redeploy, copy `backend/hardhat-deploy/.env.example` to `.env.hardhat`, add a funded deployer key, and run `npx hardhat run scripts/deploy.js --network amoy`.

## 6) Typical flow

1. Upload a document image in the UI (or use one of the built-in demo scenarios: valid / OCR failure / underage)
2. Backend runs OCR and preprocessing, stores derived values, returns a user ID
3. Client requests a proof; backend generates and verifies it with snarkjs
4. Client optionally re-verifies the same proof on-chain

## 7) Known limitations

This is a demonstration, not production KYC:

- `GenderVerifier` is compiled but not deployed, so gender proofs verify locally only
- OCR field extraction is regex-based against a specific Aadhaar layout and is sensitive to image quality
- The name/gender circuits prove equality against a hash the server computes, so they demonstrate the ZK pattern rather than a full trustless attestation. `mock-issuer/` and `experiments/` address exactly this gap for the age path, but that work is **not yet wired into this pipeline** — see below.

### Fixed since the first version

- **Leap-year bug in the age check.** The threshold was hardcoded to `6570` days (18 × 365) in
  `backend/proofgen.js`, which ignored leap days and ran **four days lenient** — someone four days
  short of their eighteenth birthday verified as an adult. The age circuit now compares encoded
  dates (`year*10000 + month*100 + day`) directly, so there is no day-count arithmetic to get
  wrong and no leap-year correction to omit. This required a new circuit, a new trusted setup, and
  a redeployed verifier contract.

### Not yet integrated

`mock-issuer/` produces an RSA-2048 signed credential and `experiments/credential-age-proof/`
proves, in a single circuit, that an issuer signed a payload **and** that the date of birth inside
those signed bytes clears an age threshold — the trustless attestation the bullet above says is
missing. It is validated standalone (256,574 constraints, ~3.6 s proving) but nothing in
`backend/` calls it yet. The pipeline described in this README still trusts server-computed
values.

## 8) Troubleshooting

- **Tesseract fails** — check the language pack downloaded correctly (`backend/eng.traineddata`)
- **snarkjs errors** — ensure circom/snarkjs versions match what the circuits were built with
- **On-chain verification fails** — most often the circuit artifacts were rebuilt without redeploying the verifiers
- **CORS or network errors** — confirm the backend is running and the Vite proxy target matches its port

## 9) Security notes

- Secrets live in `.env` (root) and `backend/hardhat-deploy/.env.hardhat`; both are gitignored and must stay that way
- Raw Aadhaar numbers are hashed and discarded, never stored or returned to the client
- Uploaded images are held in memory only and never written to disk

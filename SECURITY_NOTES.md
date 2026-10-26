# Security notes

Known security problems in this repository and what was done about them.
Checked on 2026-10-20. The v1 code is preserved at tag `v1-mock-issuer-demo`
(commit `e94fcb5`).

## 1. The v1 demo issuer's private key is public

`mock-issuer/mock_issuer_private.pem` was committed in `8e03e69` (2026-08-06)
and stayed in the tree through `e94fcb5`. Anyone with a clone can sign
credentials with it. It was the only issuer the v1 verifier page and the v1
`ZkIdPolicy` contract trusted.

- The key is removed from the tree but remains in git history, so in every
  existing clone and fork. History was not rewritten: it is a demo key, and a
  rewrite would break the v1 tag and existing clones. The key is still public.
- Its public half is listed in
  [`security/compromised-keys.json`](security/compromised-keys.json)
  (modulus, SPKI SHA-256, v1 key id). **No trusted-issuer list, registry or
  contract may ever include it.**
  [`frontend/src/verify/trustedIssuers.test.js`](frontend/src/verify/trustedIssuers.test.js)
  fails if it is added to the frontend's list, and the test issuer refuses to
  use it.
- The frontend's trusted-issuer list is now empty: no trustworthy issuer exists
  for v1 credentials.
- Test keys are generated on demand by
  [`tools/test-issuer`](tools/test-issuer/README.md) and never committed.
  `.gitignore` excludes `*.pem`, `*.key`, `*.p12` and `*.pfx`;
  [`tools/repo-checks/no_private_keys.test.mjs`](tools/repo-checks/no_private_keys.test.mjs)
  fails if a tracked file holds a private key.

## 2. The v1 contracts on Sepolia accept forged proofs. They are retired.

Read-only checks with [`tools/v1-audit`](tools/v1-audit) (`eth_call` only, no
transactions):

| Check | Result |
|---|---|
| `ZkIdPolicy` `0x8eDa6b1A54900c60C6b730796FfDd51a5327714f`: `trustedIssuers(0xa9d546d2…3dbe)`, the keccak256 of the demo key's 17 limbs | `true` at block 11956756 (publicnode and drpc agree) |
| Every transaction to the policy (Blockscout) | One: its creation, tx `0x84e98fc4…5c86`, block 11807072, which trusted only this key. `setIssuer` was never called. |
| `checkAge` on a credential with DOB 1900-01-01, signed with the public key and proved with the published v1 circuit (`forge_v1_age_proof.mjs`) | `Accepted` at block 11956793 |
| Same proof with one bit of `pi_c` flipped | `InvalidProof` |
| Same credential under a fresh random key | `UntrustedIssuer` |

So anyone can make a proof that the deployed policy accepts as "18 or older"
for any date of birth. `CredentialAgeVerifier` (`0x1052Fc75…05b1cd`) and
`CredentialMatchVerifier` (`0x7bD0f448…7641`) accept proofs under any issuer
key; only the policy checked issuers.

- All three are listed under `retired` in
  [`frontend/src/contracts/addresses.json`](frontend/src/contracts/addresses.json),
  the app no longer calls them, and `npm run deploy:policy` refuses to run.
- They stay deployed and keep accepting forgeries. Only the policy's owner
  (`0xBA01E00f7b0131DA8A1bADe4f7A1be2aFE6f90e1`) can stop that, by calling
  `setIssuer(<demo modulus limbs>, false)`. Nothing here sends that
  transaction. v2 must not reuse these contracts.
- The live v1 site (`zk-id-lime.vercel.app`, checked 2026-10-20) still ships
  the demo key's modulus as its only trusted issuer and calls the retired policy,
  so its verifier page accepts forged proof QR codes too. That lasts until it is
  redeployed from a fixed branch or taken down.

## 3. The trusted setup is a single-contributor demo setup

`cap_final.zkey` and `cmp_final.zkey` (releases `circuit-v1`,
`circuit-match-v1`) each have exactly one phase-2 contribution ("composed circuit
v1", "zkID match v1") and no beacon, on top of the powers-of-tau file in the
`circuit-v1` release (the v1 README identifies it as Hermez's; not re-checked
here). Whoever
made that contribution could forge proofs for these circuits if they kept its
randomness. This is acceptable for a demo; it is not "trustless".

v2 does not use these keys. It uses Anon Aadhaar's published proving key (105
phase-2 contributions and a beacon). `snarkjs zkey verify` against the circuit
rebuilt from source and the Hermez powers of tau passes
([docs/circuit-spec.md](docs/circuit-spec.md), section 1). That shows the
ceremony ran as recorded, not that any participant was honest; proofs stay
sound only if at least one of them destroyed their secret.

## 4. Other v1 problems, not fixed by removing the key

From the overhaul audit. Later phases remove these paths.

- **The v1 "issuer" is our own server signing OCR output** (`backend/app.js`,
  `backend/signedcredential.js`). Its signature means "the server read a photo",
  not that an identity authority attests the data; an edited photo yields a valid
  credential. On this branch the server signs with a per-process test key that
  nothing trusts.
- **Name and gender proofs disclose the claim.** The claimed gender and name hash
  are public signals; a name hash can be dictionary-tested.
- **Proofs are bearer tokens.** No verifier challenge, nullifier, expiry or
  revocation: a copied proof or QR code verifies for anyone.
- **Personal data in Supabase and logs.** `/api/upload` and `/api/demo` store the
  plaintext name and an unsalted SHA-256 of the 12-digit Aadhaar number, which
  can be brute-forced quickly. `ocr.js` and `db.js` log names. If a real card was
  ever uploaded to a deployed v1, those rows hold personal data.
- **The server sees the whole card at issuance**, and `/api/issue-credential`
  returns the raw ID number to the browser.

# v1 audit (read-only)

Checks against the retired v1 contracts on Ethereum Sepolia. They use `eth_call`
and public indexers only: no transaction is sent and no key or funds are needed.
Results are recorded in [SECURITY_NOTES.md](../../SECURITY_NOTES.md).

```bash
npm install
node check_sepolia_issuer.mjs   # does ZkIdPolicy trust a key from security/compromised-keys.json?
node forge_v1_age_proof.mjs     # forge a DOB-1900 credential with the public v1 key; ask the policy
```

`forge_v1_age_proof.mjs` needs the v1 circuit artifacts (`cd backend && npm run fetch-circuit`)
and reads the v1 key from git history (commit `e94fcb5`) into memory only.

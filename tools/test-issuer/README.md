# Test issuer (TEST ONLY)

Signs **synthetic** credentials with **ephemeral** RSA-2048 keys, so tests and
local demos have something to prove. A signature from this tool means nothing.
No verifier, registry or contract may trust any of its keys.

## Keys

- `generateTestKeys()` in [`keys.js`](keys.js) makes a key in memory. Tests use
  it, and it is gone when the process exits.
- The CLI keeps one key in `.keys/` (gitignored, private key mode 0600) so that
  `sign_credential.js` and `verify_credential.js` agree. `sign_credential.js`
  creates it on first use; `generate_keypair.js --force` replaces it.
- No key is committed. `.gitignore` excludes `*.pem`, `*.key`, `*.p12` and `*.pfx`,
  and `tools/repo-checks/no_private_keys.test.mjs` fails if a tracked file holds a
  private key.

## The v1 key is public

Until this tool replaced it, `mock-issuer/mock_issuer_private.pem` was committed
to git. It is still readable in history (commit `8e03e69` through tag
`v1-mock-issuer-demo`), so anyone can sign with it. It is listed in
[`security/compromised-keys.json`](../../security/compromised-keys.json) and must
never be trusted anywhere. `keys.js` refuses to use it. See
[SECURITY_NOTES.md](../../SECURITY_NOTES.md).

## Use

```bash
node sign_credential.js     # signs synthetic-payload.json -> out/ (gitignored)
node verify_credential.js   # 12 independent checks, including tamper controls
```

`regenerate_v1_fixtures.js` remakes the v1 proof fixtures in
`backend/hardhat-deploy/test/fixtures/` under a key that exists only while it runs. It needs the v1 circuit artifacts
(`cd backend && npm run fetch-circuit`).

// Issuers the verifier page accepts, by RSA-2048 modulus (big-endian hex). This
// list is the relying party's policy: a proof from any other key is rejected.
//
// Empty on purpose. Its only entry was the v1 demo issuer, whose private key was
// committed to git, so the page accepted forged proofs (SECURITY_NOTES.md). No
// trustworthy issuer exists for v1 credentials; v2's issuer registry replaces
// this list. trustedIssuers.test.js fails if a key from
// security/compromised-keys.json is added back.
export const TRUSTED_ISSUERS = [];

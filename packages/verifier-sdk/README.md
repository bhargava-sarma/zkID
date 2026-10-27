# @zkid/verifier-sdk

The verifier side of zkID. A website creates a single-use proof request bound
to its origin, with its rules; the holder's app proves locally and sends back
the proof; the verifier checks it against the request, the issuer registry and
its own state, and gets either the holder's per-site nullifier or a typed
failure code.

```ts
import { createVerifier } from './src/index.ts';
import { productionRegistry } from '../issuer-registry/index.ts';

const verifier = createVerifier({ verifierId: 'https://shop.example', registry: productionRegistry() });

// Keep the request in the user's session; serve it to the holder app.
const request = await verifier.createRequest({ maxAgeSeconds: 7 * 24 * 3600 });

// Later, with the proof the holder app posted back for that session:
const result = await verifier.verify(proof, publicSignals, request);
if (result.ok) console.log('account key:', result.nullifier);
else console.log('refused:', result.code);
```

## Rules

A request carries rules: what the holder's QR must show. Without any, it asks
for `{ age19: true }`.

```ts
const request = await verifier.createRequest({
  maxAgeSeconds: 7 * 24 * 3600,
  rules: { age19: true, gender: ['F'], pinCode: ['5600', '560100'], state: ['Karnataka'] },
});
// result.disclosed: { gender: 'F', pinCode: '560034', state: 'Karnataka' }
```

| Rule | Accepts | The verifier learns |
|---|---|---|
| `age19: true` | a completed age above 18 when the QR was generated | only that |
| `gender` | any of `M`, `F`, `T` listed | the holder's gender |
| `pinCode` | a listed PIN code, or one starting with a listed prefix of 1 to 5 digits | the holder's six-digit PIN code |
| `state` | a listed state, as written on Aadhaar; case and spacing are ignored | the holder's state |

Anon Aadhaar's circuit outputs gender, PIN code and state as values, not as
whether they pass, so **a rule on one of them reveals the holder's value** to
the verifier: a shop accepting 50 PIN codes learns which of the 50. The holder
app checks the rules on the device, shows the person every value it will
reveal, and proves only after they agree; a QR that breaks a rule reveals
nothing. A rule a verifier writes to admit everyone (all three genders, PIN
prefixes 1 to 9) still learns the value. The rules are part of the signal hash,
so a proof answers only the rules it was made for. `checkRules` validates
them; `decodeOutputs` reads the circuit's outputs.

## What `verify` checks, in order

| Check | Failure code |
|---|---|
| proof and nine public signals are well formed | `BAD_PROOF` |
| the proof commits to this request (signal hash), and the request names this verifier | `CHALLENGE_MISMATCH` |
| the proof uses this verifier's nullifier seed | `NULLIFIER_SEED_MISMATCH` |
| this verifier issued the request | `CHALLENGE_MISMATCH` |
| the request has not been answered | `CHALLENGE_REUSED` |
| the request has not expired (5 minutes by default) | `CHALLENGE_EXPIRED` |
| Groth16 verification under the pinned verification key | `BAD_PROOF` |
| *(from here on, the request is used up, whatever the result)* | |
| the QR's signing key is in the registry | `UNTRUSTED_ISSUER` |
| the QR's generation time is inside that key's validity window | `ISSUER_KEY_NOT_VALID` |
| with `age19`: `ageAbove18 = 1`, a completed age above 18, so **19 or older**, when the QR was generated | `AGE_NOT_PROVEN` |
| with a `gender` rule: the revealed gender is one it lists | `GENDER_NOT_ALLOWED` |
| with a `pinCode` rule: the revealed PIN code matches one it lists | `PIN_CODE_NOT_ALLOWED` |
| with a `state` rule: the revealed state is one it lists | `STATE_NOT_ALLOWED` |
| the QR is no older than the request's `maxAgeSeconds` | `CREDENTIAL_TOO_OLD` |
| the nullifier is new here (`onSeenNullifier: 'reject'`, the default) | `NULLIFIER_SEEN` |

Replay detection keys on the request's challenge, never on the proof's bytes:
a Groth16 proof can be re-randomized into different bytes that still verify.
The verifier id must be the site's origin (`https://host[:port]`; plain http
only on localhost).

What it does not defend against, such as a live relay of a request to another
person, lending, or a photocopied QR, is listed in
[docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md).

## State

`MemoryStore` keeps issued requests and seen nullifiers in one process. A
verifier running several processes needs a shared store that implements `Store`
with an atomic `useChallenge` and `addNullifier`. It stores challenges and
nullifiers, never any attribute of the holder; what a verifier does with
`result.disclosed` is up to it.

## Files

- `src/request.ts`: the request format (version 2), `nullifierSeedFor(verifierId)`
  and `signalHashFor(request)`. `src/rules.ts`: rules, and the circuit's
  gender, PIN code and state outputs. Web APIs only, so the holder app uses the
  same code.
- `vkey.json`: Anon Aadhaar v2.0.0's verification key, checked against its
  pinned SHA-256 when a verifier is created.

TypeScript, run directly by Node 22.18 or later (type stripping);
`npm run typecheck` runs `tsc`. Tests: `npm test` (eight real proofs, about 6
minutes; they need the circuit artifacts, see `packages/circuit`).

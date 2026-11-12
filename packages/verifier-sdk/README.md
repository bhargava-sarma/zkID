# @zkid/verifier-sdk

The verifier side of zkID. A website creates a single-use proof request bound
to its origin, naming the credentials it accepts (an Aadhaar QR, a DigiLocker
PAN record, or either) and its rules; the holder's app proves locally and sends
back the proof; the verifier checks it against the request, the issuer
registry and its own state, and gets either the holder's per-site nullifier or
a typed failure code.

```ts
import { createVerifier } from './src/index.ts';
import { productionRegistry } from '../issuer-registry/index.ts';

const verifier = createVerifier({ verifierId: 'https://shop.example', registry: productionRegistry() });

// Keep the request in the user's session; serve it to the holder app.
const request = await verifier.createRequest({ maxAgeSeconds: 7 * 24 * 3600, documents: ['aadhaar', 'pan'] });

// Later, with what the holder app posted back for that session:
// { document: 'aadhaar', proof, publicSignals } or { document: 'pan', proof, publicInputs }
const signals = body.document === 'pan' ? body.publicInputs : body.publicSignals;
const result = await verifier.verify(body.proof, signals, request, body.document);
if (result.ok) console.log('account key:', result.nullifier, 'proved with', result.document);
else console.log('refused:', result.code);
```

## Credentials

`documents` lists what a request accepts, in this order: `aadhaar` (a Secure
QR, proved with Anon Aadhaar's circuit) and `pan` (a DigiLocker PAN Verification
Record, proved with zkID's circuit in `packages/pan`). The default is
`['aadhaar']`. `verify`'s fourth argument names the proof's credential
(default `aadhaar`); a credential the request does not accept is
`DOCUMENT_NOT_ACCEPTED`, and leaves the request unused.

| | Aadhaar QR | PAN record |
|---|---|---|
| proof | snarkjs's Groth16 proof object | the UltraHonk proof's 14,656 bytes, in base64 |
| public values | nine public signals, decimal strings | eight public inputs, `0x` and 64 hex digits each |
| verification key | `vkey.json`, pinned | `packages/pan/artifacts/vk.json`, pinned (`PAN_VK_SHA256`) |
| credential time | when the QR was generated, to the hour | when DigiLocker last verified the PAN, to the hour |
| nullifier from | the QR's photo and the bytes after it | the PAN and the record's DigiLocker `uid` |

A verifier keeps the two credentials' nullifiers apart, so one person with both
gets two accounts at a verifier that accepts both (THREAT_MODEL A4.7). Accept
one credential if you need one account per person.

PAN proofs are checked with bb.js's WebAssembly backend, on one thread, in
milliseconds once it has started. It needs only two of Barretenberg's setup
points, which the SDK embeds: nothing is downloaded or written to disk.
`close()` stops Barretenberg's worker, so call it before the process exits.

## Rules

A request carries rules: what the holder's credential must show. Without any,
it asks for `{ age19: true }`.

```ts
const request = await verifier.createRequest({
  maxAgeSeconds: 7 * 24 * 3600,
  rules: { age19: true, gender: ['F'], pinCode: ['5600', '560100'], state: ['Karnataka'] },
});
// result.disclosed: { gender: 'F', pinCode: '560034', state: 'Karnataka' }
```

| Rule | Accepts | The verifier learns |
|---|---|---|
| `age19: true` | a QR: a completed age above 18 when it was generated. A PAN record: a date of birth on or before the request's day in India, 19 years earlier (`panDobCutoff`) | only that |
| `gender` | any of `M`, `F`, `T` listed | the holder's gender |
| `pinCode` | a listed PIN code, or one starting with a listed prefix of 1 to 5 digits; Aadhaar QRs only | the holder's six-digit PIN code |
| `state` | a listed state, as written on Aadhaar; case and spacing are ignored; Aadhaar QRs only | the holder's state |

A PAN record has no address: `createRequest` refuses a rule on PIN code or
state in a request that accepts PAN records (`checkAccepted`).

Both circuits output gender, PIN code and state as values, not as whether they
pass, so **a rule on one of them reveals the holder's value** to the verifier:
a shop accepting 50 PIN codes learns which of the 50. The holder app checks the
rules on the device, shows the person every value it will reveal, and proves
only after they agree; a credential that breaks a rule reveals nothing. A rule
a verifier writes to admit everyone (all three genders, PIN prefixes 1 to 9)
still learns the value. The rules are part of the signal hash, so a proof
answers only the rules it was made for. `checkRules` validates them;
`decodeOutputs` reads the QR circuit's outputs.

## What `verify` checks, in order

| Check | Failure code |
|---|---|
| the credential is `aadhaar` or `pan`, and the proof and its public values are well formed | `BAD_PROOF` |
| the proof commits to this request (signal hash), and the request names this verifier | `CHALLENGE_MISMATCH` |
| the proof uses this verifier's nullifier seed | `NULLIFIER_SEED_MISMATCH` |
| this verifier issued the request | `CHALLENGE_MISMATCH` |
| the request has not been answered | `CHALLENGE_REUSED` |
| the request has not expired (5 minutes by default) | `CHALLENGE_EXPIRED` |
| the request accepts this credential | `DOCUMENT_NOT_ACCEPTED` |
| a PAN proof's date-of-birth cutoff is the request's (`panDobCutoff(request.issuedAt)`) | `CHALLENGE_MISMATCH` |
| Groth16 (QR) or UltraHonk (PAN record) verification under the pinned key | `BAD_PROOF` |
| *(from here on, the request is used up, whatever the result)* | |
| the signing key is in the registry, as a key for this credential | `UNTRUSTED_ISSUER` |
| the credential's time is inside that key's validity window | `ISSUER_KEY_NOT_VALID` |
| with `age19`: the proof shows **19 or older** (above) | `AGE_NOT_PROVEN` |
| with a `gender` rule: the revealed gender is one it lists | `GENDER_NOT_ALLOWED` |
| with a `pinCode` rule: the revealed PIN code matches one it lists | `PIN_CODE_NOT_ALLOWED` |
| with a `state` rule: the revealed state is one it lists | `STATE_NOT_ALLOWED` |
| the credential is no older than the request's `maxAgeSeconds` | `CREDENTIAL_TOO_OLD` |
| the nullifier is new here (`onSeenNullifier: 'reject'`, the default) | `NULLIFIER_SEEN` |

Replay detection keys on the request's challenge, never on the proof's bytes:
a Groth16 proof can be re-randomized into different bytes that still verify.
The verifier id must be the site's origin (`https://host[:port]`; plain http
only on localhost).

What it does not defend against, such as a live relay of a request to another
person, lending, or a copied QR or record, is listed in
[docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md).

## State

`MemoryStore` keeps issued requests and seen nullifiers in one process. A
verifier running several processes needs a shared store that implements `Store`
with an atomic `useChallenge` and `addNullifier`; PAN nullifiers reach it with
the prefix `pan:`. It stores challenges and nullifiers, never any attribute of
the holder; what a verifier does with `result.disclosed` is up to it.

## Files

- `src/request.ts`: the request format (version 3: it also carries `issuedAt`
  and `documents`), `nullifierSeedFor(verifierId)` and `signalHashFor(request)`.
  `src/rules.ts`: rules, the QR circuit's gender, PIN code and state outputs,
  and a PAN proof's date-of-birth cutoff. Web APIs only, so the holder app uses
  the same code.
- `vkey.json`: Anon Aadhaar v2.0.0's verification key, checked against its
  pinned SHA-256 when a verifier is created. The PAN verification key is read
  from `packages/pan`, and checked the same way.

TypeScript, run directly by Node 22.18 or later (type stripping);
`npm run typecheck` runs `tsc`. Tests: `npm test` (nine Aadhaar proofs, about 6
minutes, which need the circuit artifacts, see `packages/circuit`; and nine PAN
proofs, about a minute, which need `packages/pan` installed).

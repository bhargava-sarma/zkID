# @zkid/pan

zkID's circuit for DigiLocker PAN Verification Records, and what the holder app
and the verifier SDK need around it. The circuit is zkID's own, in Noir 1.0.0,
proved with Barretenberg's UltraHonk (`@aztec/bb.js` 5.3.0), which needs no
setup ceremony of its own. What it checks, what it does not, and what it costs
are in [docs/circuit-spec.md](../../docs/circuit-spec.md), section 7; its
attacks and tests are in [docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md).
It has not been reviewed by anyone outside this project.

```bash
cd packages/pan
npm install
npm test                 # reader, c14n, the circuit on synthetic records, a proof (about a minute)
npm run check            # constants.nr and the pinned build still match circuit/ (CI runs it)
npm run build            # remake artifacts/ after changing the circuit
PAN_XML=<file>[:<file>] npm test   # also real records, locally: nothing of them is printed
```

A first proof in Node downloads Barretenberg's setup points from Aztec's CDN
into `~/.bb-crs` (about 20 MB).

## Files

| | |
|---|---|
| `circuit/` | the Noir circuit: `main.nr`, with `sha1.nr`, `bignum.nr` (2048-bit RSA arithmetic, checked limb by limb), `poseidon2.nr` (Barretenberg's Poseidon2 sponge) and `constants.nr`, which `gen-constants.mjs` writes from `format.mjs` |
| `artifacts/` | the compiled program and its verification key, pinned by SHA-256 (`vk.json` records both hashes); `build.mjs` makes them, the same on every machine |
| `format.mjs` | the record's layout as the circuit reads it: its fixed head, DigiLocker's exact `SignedInfo`, the limits |
| `record.mjs` | reads a record in the browser or Node: canonicalizes it (`c14n.mjs`, exclusive-c14n), checks the digest and DigiLocker's signature against trusted keys, checks the layout, and finds the fields. Refuses anything else with a typed `PanError` |
| `input.mjs` | the circuit input for a record, and the outputs a proof of it will have |
| `prove.mjs` | executes the circuit (`@noir-lang/noir_js`) and proves (bb.js), in the browser or Node |
| `verify.mjs` | checks a proof (Node), with the two setup points it needs embedded: no download |
| `public.mjs`, `keyhash.mjs`, `limbs.mjs` | the public inputs' order and decoding; the key hash (`panKeyHash`) |
| `keys.json` | DigiLocker's document-signing key, with its provenance; `packages/issuer-registry` builds its entry from it |
| `synthetic.mjs` | SYNTHETIC records for tests and the demo: DigiLocker's layout, fake values ("SYNTHETIC TEST PERSON", PAN `TESTP0000T`), signed by an ephemeral TEST key under a self-signed TEST certificate |

## Real records

Real records hold a person's PAN, name and date of birth: they stay out of git
and out of logs. The tests that take them (`PAN_XML`) print only whether they
passed. `keys.json` holds DigiLocker's public key and the SHA-256 of its
certificate, not the certificate, whose subject includes a person's e-mail
address.

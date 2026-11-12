# Demo relying party

A page ("Demo shop") that uses the zkID verifier SDK end to end. Each visitor
sets the shop's rules for their own visit: the credentials it accepts (an
Aadhaar QR, a DigiLocker PAN record, or either; both by default), 19 or older,
and the genders, PIN codes and states it accepts. It never sees a QR or a
record: it issues a request with those rules, the holder app checks them and
proves on the person's device, and only the proof comes back. One account per
nullifier. A rule on gender, PIN code or state reveals the holder's value of
that field ([DECISIONS](../../docs/DECISIONS.md), section 10), and a rule on PIN
code or state needs a shop that accepts only Aadhaar QRs (a PAN record has no
address); the result screen shows what the shop learned, and with which
credential.

It runs two ways:

- **Locally** (`server.ts`): one shop per process, state in memory. `--demo`
  makes it trust TEST issuer keys that this machine generated.
- **Hosted** (`vercel/`): the holder app and two shops on Vercel, for anyone to
  try with their own Aadhaar QR or PAN record, or a synthetic test one. State
  is in Upstash Redis. See [Hosted demo](#hosted-demo-vercel).

The pages (`views.ts`, and the holder app's `frontend/src/App.css`) load no
fonts or scripts from anywhere else.

## Run it locally

Install once:

```bash
(cd packages/circuit && npm install)
(cd packages/pan && npm install)
(cd packages/verifier-sdk && npm install)
(cd apps/demo-rp && npm install)
(cd frontend && npm install)
```

Then:

```bash
cd apps/demo-rp && npm run setup      # TEST issuer keys, a synthetic QR image and PAN record in .demo/
cd frontend && npm run dev:demo       # holder app on http://localhost:5173, trusting those keys
cd apps/demo-rp && npm start          # verifier A on http://localhost:4101
cd apps/demo-rp && npm run start:b    # verifier B on http://localhost:4102 (optional)
```

Open http://localhost:4101, choose **Verify with zkID**, pick **Aadhaar QR** in
the holder app and give it `apps/demo-rp/.demo/synthetic-qr.png`, or pick **PAN
record** and give it `apps/demo-rp/.demo/synthetic-pan.xml`. The first QR proof
downloads Anon Aadhaar's circuit files (about 300 MB, then cached by the
browser). Proving took about 45 s and 5 GB of memory on a 4-core desktop; the
holder app's single thread option needs about half the memory and takes
longer. On a phone, use one thread (the default there): an 8-core phone proved
in 79 s that way, and ran out of memory with several threads. A PAN proof
downloads about 20 MB the first time and took 14 s on the same phone, on 8
threads; Vite's dev server sends the headers that allow several threads. The
synthetic PAN record counts as verified when `npm run setup` ran, so shops
accept it for 7 days. Rerunning `npm run setup` makes new keys: restart the
holder app afterwards.

What to look for:

- Verifier A grants account #001 and shows the start of its nullifier, and
  which credential proved it. Proving with the PAN record as well gets another
  account: to the shop it is another person (THREAT_MODEL A4.7).
- Under **Your rules**, pick Female and save: the synthetic QR (a man) is now
  stopped in the holder app before proving, with `GENDER_NOT_ACCEPTED`. Rules
  that the QR meets show their values in the holder app before you prove, and
  on the shop's result screen after.
- Verifier B, proved to with the same QR, shows a different nullifier: the two
  sites cannot match their records by it.
- In a second browser (or after clearing cookies), proving to A again with the
  same QR or record is refused with `NULLIFIER_SEEN`: one account per
  credential per site.
- Under **Your rules**, untick **PAN record** to accept Aadhaar QRs only, which a
  rule on PIN code or state needs.
- **Verify on my phone** shows the request as a QR and waits for the proof. A
  phone can only use it if both the verifier and the holder app are reachable
  from the phone, the holder app over HTTPS (browsers allow WebCrypto only in
  secure contexts). Set `ZKID_VERIFIER_ID` to the verifier's public origin and
  `--holder` to the holder app's.

## Hosted demo (Vercel)

One Vercel project, built by `vercel/build.mjs`, serves:

- **The holder app's demo build** at `https://<holder domain>/holder/`, served
  cross-origin isolated so the PAN prover can use several threads. It trusts
  UIDAI's and DigiLocker's keys and this deployment's TEST keys. A real Aadhaar
  QR works if it was generated in the last 7 days, as on a freshly downloaded
  e-Aadhaar, and a real PAN record if DigiLocker verified it in the last 7 days
  (in DigiLocker, fetch the record again from the Income Tax Department, then
  download its XML): the holder app reads it and proves in the browser, and
  sends only the proof.
- **A demo shop on every other domain** of the project. A shop's verifier id is
  its origin, so two domains are two shops, and the same QR or record gets
  unrelated nullifiers at them. Each shop's page makes test QRs and test PAN
  records, synthetic and signed with the TEST keys: an adult or someone 17
  years old today, with the gender (and for a QR, the PIN code and state)
  picked.

The build compiles the shops (`app.ts`, `vercel/handler.ts`) and the packages
they import to JavaScript, makes two new TEST issuer keys (one for QRs, one for
PAN records), builds the holder app with them under `/holder/`, and writes
Vercel's Build Output API to `.vercel/output`. It installs the holder app's
packages from its lockfile, and again whenever the lockfile changes: Vercel can
restore an older `node_modules` from its build cache. The keys' private halves go only
into the function, which signs the samples with them. Each deployment makes new
keys, so samples from an earlier deployment stop working. `/holder/` is static,
so every domain of the project serves it; the shops send people to the
holder's domain. The function carries bb.js's WebAssembly for PAN proofs (7.5
MB in all); checking one needs no download.

What the shops keep, in Upstash Redis: each request and whether its challenge
was used (16 minutes); the browser session with its last result, which is the
per-site code (nullifier), the issuer key and the hour the QR was generated
(a day); and the per-site code of each accepted proof (7 days, after which the
same person can open a second account at that shop). No QR, record, field of
either or proof is stored, and the logs say only "accepted" or "refused".

### Set it up

1. In Vercel, **Add New → Project**, and import this repository. Set **Root
   Directory** to `apps/demo-rp` and keep **Include files outside the root
   directory in the Build Step** on. `vercel.json` sets the build. Deploy.
2. In the project's **Storage** tab, create an Upstash Redis database (the free
   plan is enough) and connect it to the project. That sets
   `KV_REST_API_URL` and `KV_REST_API_TOKEN`.
3. In **Settings → Domains**, add two domains for the shops, for example
   `<name>-shop-a.vercel.app` and `<name>-shop-b.vercel.app`. The project's own
   `<project>.vercel.app` is the holder's.
4. In **Settings → Environment Variables**, set `ZKID_DEMO_HOLDER` to
   `https://<project>.vercel.app/holder/`. It is not guessed from the domains:
   with several, nothing else says which one is the holder's.
5. Redeploy, and open a shop's domain.

Until steps 2 and 4 are done, every shop page says which setting is missing.

### Try the build locally

```bash
cd apps/demo-rp
node vercel/build.mjs            # writes .vercel/output
node vercel/serve-output.mjs     # holder http://localhost:4100/holder/, shops http://localhost:4101 and :4102
```

`serve-output.mjs` routes as Vercel does: the headers `config.json` sets,
static files first, everything else to the function. Without
`KV_REST_API_URL`, it runs an in-memory stand-in for Upstash's REST API.

## Local server

`node server.ts --port <port> [--holder <url>] [--demo]`. The verifier id is
`http://localhost:<port>` unless `ZKID_VERIFIER_ID` is set. Requests ask for a
QR, or a PAN record's verification, at most 7 days old, and expire after 15
minutes.

| Route | |
|---|---|
| `GET /` | the page, with this browser session's rules and last result |
| `POST /rules` | saves this session's rules (form fields `document`, `age19`, `gender`, `pin`, `state`) |
| `POST /start`, `POST /start?qr` | a new request with this session's rules; redirects to the holder app, or to `/qr` |
| `GET /qr` | the request as a QR; polls `/zkid/status` |
| `GET /zkid/request/<challenge>` | the request, for the holder app (CORS: the holder origin only) |
| `POST /zkid/response/<challenge>` | `{ document, proof, publicSignals }` (or `publicInputs`, for a PAN proof) from the holder app; runs `verify` |
| `GET /zkid/status` | this session's result |
| `GET /sample-qr.png?age=adult\|minor&gender=M\|F\|T&pin=<6 digits>&state=<state>` | a synthetic QR signed with the TEST key (hosted demo only); by default an adult man, 560034, Karnataka |
| `GET /sample-pan.xml?age=adult\|minor&gender=M\|F\|T` | a synthetic PAN record signed with the TEST key, verified now (hosted demo only); by default an adult man. Each is another person |

The server logs only "accepted" or "refused" with a failure code. The hosted
shops answer the same routes.

## End-to-end test

```bash
cd apps/demo-rp
npx playwright install chromium   # once
npm run test:e2e
```

`e2e/flow.test.ts` runs the setup, builds the holder app in demo mode, starts
verifiers A and B, and drives headless Chromium through six real proofs, three
from the synthetic QR and three from the synthetic PAN record (about 4 minutes
on the machine above), with the holder app cross-origin isolated as hosted. It
checks the outcomes above, that each posted proof reveals only the age bit
(THREAT_MODEL T6.1), and that no request made by the pages or the proving
workers carries any part of the QR or the record (T6.3).

`e2e/hosted.test.ts` builds the hosted demo and serves a copy of its output
from outside the repository, so a file the function needs but the build left
out fails here. With test QRs and a test PAN record made by shop A, it makes
five more proofs (account #001 at A, a different nullifier at B,
`NULLIFIER_SEEN` at A again, one from the PAN record, which the function checks
with bb.js, and one under rules on gender, PIN code and state set through the
shop's form), and checks that the holder app is cross-origin isolated and the
shops are not, that an under-19 QR or PAN record and a QR that breaks a gender
rule are stopped before proving (T6.4), that a rule on state is refused for a
shop that accepts PAN records, that each proof reveals exactly the fields its
rules name (T6.1), that no request carries any other part of the QRs or the
record (T6.3), and that without `ZKID_DEMO_HOLDER` the shops say what to set.

# Demo relying party

An age-gated page ("Demo shop") that uses the zkID verifier SDK end to end. It
never sees a QR: it issues a request, the holder app proves on the person's
device, and only the proof comes back. One account per nullifier.

It runs two ways:

- **Locally** (`server.ts`): one shop per process, state in memory. `--demo`
  makes it trust a TEST issuer key that this machine generated.
- **Hosted** (`vercel/`): the holder app and two shops on Vercel, for anyone to
  try with their own Aadhaar QR or a synthetic sample. State is in Upstash
  Redis. See [Hosted demo](#hosted-demo-vercel).

## Run it locally

Install once:

```bash
(cd packages/circuit && npm install)
(cd packages/verifier-sdk && npm install)
(cd apps/demo-rp && npm install)
(cd frontend && npm install)
```

Then:

```bash
cd apps/demo-rp && npm run setup      # TEST issuer key + synthetic QR image in .demo/
cd frontend && npm run dev:demo       # holder app on http://localhost:5173, trusting that key
cd apps/demo-rp && npm start          # verifier A on http://localhost:4101
cd apps/demo-rp && npm run start:b    # verifier B on http://localhost:4102 (optional)
```

Open http://localhost:4101, choose **Verify age with zkID**, and give the holder
app `apps/demo-rp/.demo/synthetic-qr.png`. The first proof downloads Anon
Aadhaar's circuit files (about 300 MB, then cached by the browser). Proving
took about 45 s and 5 GB of memory on a 4-core desktop; the holder app's single
thread option needs about half the memory and takes longer. On a phone, use one
thread (the default there): an 8-core phone proved in 79 s that way, and ran
out of memory with several threads. Rerunning
`npm run setup` makes a new key: restart the holder app afterwards.

What to look for:

- Verifier A grants account #1 and shows the start of its nullifier.
- Verifier B, proved to with the same QR, shows a different nullifier: the two
  sites cannot match their records by it.
- In a second browser (or after clearing cookies), proving to A again is
  refused with `NULLIFIER_SEEN`: one account per QR per site.
- **Verify on my phone** shows the request as a QR and waits for the proof. A
  phone can only use it if both the verifier and the holder app are reachable
  from the phone, the holder app over HTTPS (browsers allow WebCrypto only in
  secure contexts). Set `ZKID_VERIFIER_ID` to the verifier's public origin and
  `--holder` to the holder app's.

## Hosted demo (Vercel)

One Vercel project, built by `vercel/build.mjs`, serves:

- **The holder app's demo build** at `https://<holder domain>/holder/`. It
  trusts UIDAI's keys and this deployment's TEST key. A real Aadhaar QR works
  if it was generated in the last 7 days, as on a freshly downloaded e-Aadhaar:
  the holder app reads it and proves in the browser, and sends only the proof.
- **A demo shop on every other domain** of the project. A shop's verifier id is
  its origin, so two domains are two shops, and the same QR gets unrelated
  nullifiers at them. Each shop's page links to two sample QRs, synthetic and
  signed with the TEST key: an adult, and someone 17 years old today.

The build compiles the shops (`app.ts`, `vercel/handler.ts`) and the packages
they import to JavaScript, makes a new TEST issuer key, builds the holder app
with that key under `/holder/`, and writes Vercel's Build Output API to
`.vercel/output`. The key's private half goes only into the function, which
signs the sample QRs with it. Each deployment makes a new key, so sample QRs
from an earlier deployment stop working. `/holder/` is static, so every domain
of the project serves it; the shops send people to the holder's domain.

What the shops keep, in Upstash Redis: each request and whether its challenge
was used (16 minutes); the browser session with its last result, which is the
per-site code (nullifier), the issuer key and the hour the QR was generated
(a day); and the per-site code of each accepted proof (7 days, after which the
same person can open a second account at that shop). No QR, field of it or
proof is stored, and the logs say only "accepted" or "refused".

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

`serve-output.mjs` routes as Vercel does: static files first, everything else
to the function. Without `KV_REST_API_URL`, it runs an in-memory stand-in for
Upstash's REST API.

## Local server

`node server.ts --port <port> [--holder <url>] [--demo]`. The verifier id is
`http://localhost:<port>` unless `ZKID_VERIFIER_ID` is set. Requests ask for a
QR at most 7 days old and expire after 15 minutes.

| Route | |
|---|---|
| `GET /` | the page, with this browser session's last result |
| `POST /start`, `POST /start?qr` | a new request; redirects to the holder app, or to `/qr` |
| `GET /qr` | the request as a QR; polls `/zkid/status` |
| `GET /zkid/request/<challenge>` | the request, for the holder app (CORS: the holder origin only) |
| `POST /zkid/response/<challenge>` | `{ proof, publicSignals }` from the holder app; runs `verify` |
| `GET /zkid/status` | this session's result |
| `GET /sample-qr.png`, `GET /sample-qr.png?minor` | a synthetic QR signed with the TEST key, adult or under 19 (hosted demo only) |

The server logs only "accepted" or "refused" with a failure code. The hosted
shops answer the same routes.

## End-to-end test

```bash
cd apps/demo-rp
npx playwright install chromium   # once
npm run test:e2e
```

`e2e/flow.test.ts` runs the setup, builds the holder app in demo mode, starts
verifiers A and B, and drives headless Chromium through three real proofs
(about 3 minutes on the machine above). It checks the outcomes above, that each
posted proof reveals only the age bit (THREAT_MODEL T6.1), and that no request
made by the pages or the proving worker carries any part of the QR (T6.3).

`e2e/hosted.test.ts` builds the hosted demo and serves a copy of its output
from outside the repository, so a file the function needs but the build left
out fails here. With sample QRs downloaded from shop A, it makes three more
proofs (account #1 at A, a different nullifier at B, `NULLIFIER_SEEN` at A
again), and checks that the under-19 sample is stopped before proving, that no
request carries any part of the QR, and that without `ZKID_DEMO_HOLDER` the
shops say what to set.

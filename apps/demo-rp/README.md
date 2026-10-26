# Demo relying party

An age-gated page ("Demo shop") that uses the zkID verifier SDK end to end. It
never sees a QR: it issues a request, the holder app proves on the person's
device, and only the proof comes back. One account per nullifier.

Local use only: state is in memory, and `--demo` makes it trust a TEST issuer
key that this machine generated.

## Run it

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
thread option needs about half the memory and takes longer. Rerunning
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

## Server

`node server.ts --port <port> [--holder <origin>] [--demo]`. The verifier id is
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

The server logs only "accepted" or "refused" with a failure code.

## End-to-end test

```bash
cd apps/demo-rp
npm run test:e2e    # PLAYWRIGHT=<path to playwright> if it is not installed here
```

It runs the setup, builds the holder app in demo mode, starts verifiers A and
B, and drives headless Chromium through three real proofs (about 3 minutes on
the machine above). It checks the outcomes above, that each posted proof
reveals only the age bit (THREAT_MODEL T6.1), and that no request made by the
pages or the proving worker carries any part of the QR (T6.3).

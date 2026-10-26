// Demo relying party: an age-gated page that uses the verifier SDK end to end.
// It never sees a QR: it issues a request, the holder app proves on the
// person's device, and only the proof comes back. One account per nullifier.
// State is in memory, so this is for local use (THREAT_MODEL S6).
//
// Usage: node server.ts --port 4101 [--holder http://localhost:5173] [--demo]
//   --holder  where the holder app runs (default: the frontend's Vite dev server).
//   --demo    also trusts the local demo's TEST issuer (run setup-demo.mjs first).
//             Without it, only UIDAI's keys from the issuer registry are trusted.
// The verifier id is http://localhost:<port> unless ZKID_VERIFIER_ID is set.

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import QRCode from 'qrcode';
import { createVerifier, type ProofRequest, type VerifyResult } from '../../packages/verifier-sdk/src/index.ts';
import { checkRegistry, productionRegistry, testRegistry, type Registry } from '../../packages/issuer-registry/index.ts';

const arg = (name: string) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
};
const port = Number(arg('--port') ?? 4101);
const holder = new URL(arg('--holder') ?? 'http://localhost:5173').origin;
const verifierId = process.env.ZKID_VERIFIER_ID ?? `http://localhost:${port}`;
const demo = process.argv.includes('--demo');

function registry(): Registry {
  const uidai = productionRegistry();
  if (!demo) return uidai;
  const { keys } = JSON.parse(fs.readFileSync(new URL('./.demo/test-issuer.json', import.meta.url), 'utf8'));
  const test = testRegistry(
    keys.map((k: { id: string; modulus: string; keyHash: string }) => ({
      id: k.id,
      keyHash: k.keyHash,
      publicKey: crypto.createPublicKey({ key: { kty: 'RSA', n: Buffer.from(k.modulus, 'hex').toString('base64url'), e: 'AQAB' }, format: 'jwk' }),
    })),
  );
  return checkRegistry({ production: false, keys: [...uidai.keys, ...test.keys] });
}

// 15 minutes rather than the SDK's 5: on a phone, proving alone can take minutes.
const verifier = createVerifier({ verifierId, registry: registry(), requestTtlSeconds: 15 * 60 });

// Session (cookie) -> its latest request and result. Challenge -> request and session.
const sessions = new Map<string, { challenge?: string; result?: VerifyResult; account?: number }>();
const pending = new Map<string, { request: ProofRequest; sid: string }>();
// Browsers share cookies across the ports of one host, so each demo verifier on
// localhost needs its own cookie name, or they overwrite each other's session.
const COOKIE = `zkid_demo_${new URL(verifierId).port || 'site'}`;
const cookieValue = new RegExp(`(?:^|;\\s*)${COOKIE}=([0-9a-f]{32})`);
const accounts = new Map<string, number>(); // nullifier -> account number

const holderUrl = (challenge: string) => `${holder}/?request=${encodeURIComponent(`${verifierId}/zkid/request/${challenge}`)}`;

const html = (body: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo shop, ${verifierId}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}.ok{color:#1b6e3a}.error{color:#a3261b}button{font:inherit;padding:.5rem 1rem;margin:0 .5rem .5rem 0}form{display:inline}a{overflow-wrap:anywhere}</style></head>
<body><h1>Demo shop</h1><p>Verifier: <code>${verifierId}</code>${demo ? ' (demo: also trusts a local TEST issuer)' : ''}</p>${body}</body></html>`;

const page = (session: { result?: VerifyResult; account?: number }) => {
  const r = session.result;
  const status = !r
    ? '<p>This page is for people who are 19 or older.</p>'
    : r.ok
      ? `<p class="ok" data-testid="granted">Access granted. Your account here is <strong>#${session.account}</strong> (code <code>${r.nullifier.slice(0, 8)}…</code>).</p>`
      : `<p class="error" data-testid="refused">Refused: <strong>${r.code}</strong>. ${r.detail}</p>`;
  return html(`${status}
<form method="post" action="/start"><button>Verify age with zkID</button></form>
<form method="post" action="/start?qr"><button>Verify on my phone</button></form>
<p><small>The age check runs on your device, on your own QR. This site receives a proof and a per-site code, nothing else.</small></p>`);
};

// The request as a QR, for the holder app on another device. This page polls
// for the result, which arrives when that device posts the proof.
const qrPage = (qr: string, url: string) =>
  html(`<p>Scan this with your phone's camera to open the request in zkID there:</p>
<p><img data-testid="request-qr" src="${qr}" alt="QR code of the zkID request" width="300" height="300"></p>
<p><small><a href="${url}">${url}</a></small></p>
<p aria-live="polite">Waiting for the proof. The request expires in 15 minutes.</p>
<script>setInterval(async () => { if (await (await fetch('/zkid/status')).json()) location = '/'; }, 2000);</script>`);

function sessionOf(req: http.IncomingMessage, res: http.ServerResponse) {
  let sid = cookieValue.exec(req.headers.cookie ?? '')?.[1];
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, {});
    res.setHeader('set-cookie', `${COOKIE}=${sid}; HttpOnly; SameSite=Lax; Path=/`);
  }
  return { sid, session: sessions.get(sid)! };
}

const cors = { 'access-control-allow-origin': holder, 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'content-type' };
const json = (res: http.ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json', ...cors });
  res.end(JSON.stringify(body));
};

async function readJson(req: http.IncomingMessage): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 64 * 1024) throw new Error('body too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', verifierId);
  const challenge = /^\/zkid\/(?:request|response)\/([0-9a-f]{64})$/.exec(url.pathname)?.[1];
  try {
    if (req.method === 'GET' && url.pathname === '/') {
      const { session } = sessionOf(req, res);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(page(session));
    }
    if (req.method === 'POST' && url.pathname === '/start') {
      const { sid, session } = sessionOf(req, res);
      const request = await verifier.createRequest({ maxAgeSeconds: 7 * 86400 });
      pending.set(request.challenge, { request, sid });
      Object.assign(session, { challenge: request.challenge, result: undefined, account: undefined });
      res.writeHead(303, { location: url.searchParams.has('qr') ? '/qr' : holderUrl(request.challenge) });
      return res.end();
    }
    if (req.method === 'GET' && url.pathname === '/qr') {
      const { session } = sessionOf(req, res);
      if (!session.challenge || session.result) {
        res.writeHead(303, { location: '/' });
        return res.end();
      }
      const target = holderUrl(session.challenge);
      const qr = await QRCode.toDataURL(target, { errorCorrectionLevel: 'M', margin: 4, scale: 6 });
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(qrPage(qr, target));
    }
    if (req.method === 'GET' && url.pathname === '/zkid/status') {
      const { session } = sessionOf(req, res);
      return json(res, 200, session.result ? { ...session.result, account: session.account } : null);
    }
    if (challenge && req.method === 'OPTIONS') {
      res.writeHead(204, cors);
      return res.end();
    }
    if (challenge && req.method === 'GET' && url.pathname.startsWith('/zkid/request/')) {
      const entry = pending.get(challenge);
      if (!entry) return json(res, 404, { error: 'unknown request' });
      return json(res, 200, { request: entry.request, responseUrl: `${verifierId}/zkid/response/${challenge}`, returnUrl: `${verifierId}/` });
    }
    if (challenge && req.method === 'POST' && url.pathname.startsWith('/zkid/response/')) {
      const entry = pending.get(challenge);
      if (!entry) return json(res, 404, { ok: false, code: 'CHALLENGE_MISMATCH', detail: 'unknown request' });
      const body = (await readJson(req)) as { proof?: unknown; publicSignals?: unknown };
      const result = await verifier.verify(body?.proof, body?.publicSignals, entry.request);
      const session = sessions.get(entry.sid)!;
      session.result = result;
      if (result.ok) {
        if (!accounts.has(result.nullifier)) accounts.set(result.nullifier, accounts.size + 1);
        session.account = accounts.get(result.nullifier);
      }
      console.log(`${new Date().toISOString()} ${verifierId} ${result.ok ? `accepted, account #${session.account}` : `refused ${result.code}`}`);
      return json(res, 200, result.ok ? { ok: true, account: session.account } : result);
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  } catch (err) {
    json(res, 400, { error: (err as Error).message });
  }
});

server.listen(port, () => console.log(`demo verifier ${verifierId}${demo ? ' (demo)' : ''}; holder app ${holder}`));

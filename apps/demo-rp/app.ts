// Demo relying party ("Demo shop"): an age-gated page that uses the verifier SDK
// end to end. It never sees a QR: it issues a request, the holder app proves on
// the person's device, and only the proof comes back. One account per
// nullifier. createDemoApp serves one or more shops, each identified by the
// origin a request arrives on: server.ts runs one locally, vercel/handler.ts
// several on Vercel.

import crypto from 'node:crypto';
import type http from 'node:http';
import QRCode from 'qrcode';
import { createVerifier, type ProofRequest, type Store, type VerifyResult } from '../../packages/verifier-sdk/src/index.ts';
import { checkRegistry, productionRegistry, testRegistry, type Registry } from '../../packages/issuer-registry/index.ts';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../../packages/secure-qr/synthetic.mjs';
import type { KV } from './kv.ts';

const REQUEST_TTL = 15 * 60; // the SDK's default is 5 minutes; on a phone, proving alone can take minutes
const MAX_AGE = 7 * 86400; // a QR generated in the last 7 days
const SESSION_TTL = 86400;
const CODE_TTL = 7 * 86400; // how long a shop remembers a per-site code

export interface DemoOptions {
  // The shop's verifier id (its origin) for this request, or null if the request is not for a shop.
  siteFor(req: http.IncomingMessage): string | null;
  holder: string; // the holder app's URL
  registry: Registry;
  kv: KV;
  // The demo's TEST issuer, if the registry trusts one. With its private key, the shops hand out sample QRs.
  testIssuer?: { label: string; privateKey?: crypto.KeyObject };
}

type Session = { challenge?: string; result?: VerifyResult; account?: number };

// UIDAI's keys plus the demo's TEST keys, as setup-demo.mjs and vercel/build.mjs write them.
export function demoRegistry(testKeys: { id: string; modulus: string; keyHash: string }[]): Registry {
  const test = testRegistry(
    testKeys.map((k) => ({
      id: k.id,
      keyHash: k.keyHash,
      publicKey: crypto.createPublicKey({ key: { kty: 'RSA', n: Buffer.from(k.modulus, 'hex').toString('base64url'), e: 'AQAB' }, format: 'jwk' }),
    })),
  );
  return checkRegistry({ production: false, keys: [...productionRegistry().keys, ...test.keys] });
}

class BadRequest extends Error {}

// The SDK's store, in the KV, one namespace per shop.
class KvStore implements Store {
  private kv: KV;
  private prefix: string;

  constructor(kv: KV, prefix: string) {
    this.kv = kv;
    this.prefix = prefix;
  }

  async putRequest(request: ProofRequest) {
    await this.kv.set(`${this.prefix}req:${request.challenge}`, JSON.stringify(request), REQUEST_TTL + 60);
  }

  async getRequest(challenge: string) {
    const request = await this.kv.get(`${this.prefix}req:${challenge}`);
    if (!request) return undefined;
    return { request: JSON.parse(request) as ProofRequest, used: (await this.kv.get(`${this.prefix}used:${challenge}`)) !== null };
  }

  async useChallenge(challenge: string) {
    if (!(await this.kv.get(`${this.prefix}req:${challenge}`))) return false;
    return this.kv.set(`${this.prefix}used:${challenge}`, '1', REQUEST_TTL + 60, true);
  }

  async addNullifier(nullifier: string) {
    return this.kv.set(`${this.prefix}nul:${nullifier}`, '1', CODE_TTL, true);
  }
}

const escape = (text: string) => text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

async function readJson(req: http.IncomingMessage): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 64 * 1024) throw new BadRequest('body too large');
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new BadRequest('body is not JSON');
  }
}

// A synthetic QR, signed by the TEST issuer, as a PNG. `minor`: 17 years old today.
async function sampleQr(privateKey: crypto.KeyObject, minor: boolean) {
  const now = new Date();
  const dob = minor ? `${String(now.getUTCDate()).padStart(2, '0')}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${now.getUTCFullYear() - 17}` : '01-01-1990';
  const { text } = makeSyntheticSecureQr(privateKey, {
    version: 'V5',
    photo: syntheticPhoto(900),
    trailing: unknownTrailer(27),
    fields: { ...syntheticFields({ generatedAt: now }), dob },
  });
  // Numeric mode, as UIDAI's codes; low error correction keeps 3,000+ digits readable.
  return QRCode.toBuffer([{ data: text, mode: 'numeric' }], { errorCorrectionLevel: 'L', margin: 4, scale: 4 });
}

export function createDemoApp(options: DemoOptions) {
  const { kv, registry, testIssuer } = options;
  const holder = new URL(options.holder);
  const cors = { 'access-control-allow-origin': holder.origin, 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'content-type' };
  const verifiers = new Map<string, ReturnType<typeof createVerifier>>();
  const verifierFor = (site: string) => {
    if (!verifiers.has(site)) {
      verifiers.set(site, createVerifier({ verifierId: site, registry, store: new KvStore(kv, `zkid:${site}:`), requestTtlSeconds: REQUEST_TTL }));
    }
    return verifiers.get(site)!;
  };

  const holderUrl = (site: string, challenge: string) => `${holder.href}?request=${encodeURIComponent(`${site}/zkid/request/${challenge}`)}`;

  const html = (site: string, body: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo shop, ${escape(site)}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}.ok{color:#1b6e3a}.error{color:#a3261b}button{font:inherit;padding:.5rem 1rem;margin:0 .5rem .5rem 0}form{display:inline}a{overflow-wrap:anywhere}</style></head>
<body><h1>Demo shop</h1><p>Verifier: <code>${escape(site)}</code></p>${body}</body></html>`;

  const page = (site: string, session: Session) => {
    const r = session.result;
    const status = !r
      ? '<p>This page is for people who are 19 or older.</p>'
      : r.ok
        ? `<p class="ok" data-testid="granted">Access granted. Your account here is <strong>#${session.account}</strong> (code <code>${r.nullifier.slice(0, 8)}…</code>).</p>`
        : `<p class="error" data-testid="refused">Refused: <strong>${escape(r.code)}</strong>. ${escape(r.detail)}</p>`;
    const samples = testIssuer?.privateKey
      ? ` No Aadhaar QR at hand? Download a sample QR: <a href="/sample-qr.png">adult</a>, <a href="/sample-qr.png?minor">under 19</a> (synthetic, not UIDAI).`
      : '';
    return html(
      site,
      `${status}
<form method="post" action="/start"><button>Verify age with zkID</button></form>
<form method="post" action="/start?qr"><button>Verify on my phone</button></form>
<p><small>You need an image of the QR on an e-Aadhaar downloaded in the last 7 days. The age check runs on your device, on your own QR. This site receives a proof and a per-site code, nothing else, and keeps the code for 7 days.</small></p>
${testIssuer ? `<p><small>Demo: besides UIDAI, this shop trusts ${escape(testIssuer.label)}.${samples}</small></p>` : ''}`,
    );
  };

  // The request as a QR, for the holder app on another device. This page polls
  // for the result, which arrives when that device posts the proof.
  const qrPage = (site: string, qr: string, url: string) =>
    html(
      site,
      `<p>Scan this with your phone's camera to open the request in zkID there:</p>
<p><img data-testid="request-qr" src="${qr}" alt="QR code of the zkID request" width="300" height="300"></p>
<p><small><a href="${escape(url)}">${escape(url)}</a></small></p>
<p aria-live="polite">Waiting for the proof. The request expires in 15 minutes.</p>
<script>setInterval(async () => { if (await (await fetch('/zkid/status')).json()) location = '/'; }, 2000);</script>`,
    );

  // Browsers share cookies across the ports of one host, so each shop on
  // localhost needs its own cookie name, or they overwrite each other's session.
  const cookieName = (site: string) => `zkid_demo_${new URL(site).port || 'site'}`;
  const sessionKey = (site: string, sid: string) => `zkid:${site}:sess:${sid}`;
  const saveSession = (site: string, sid: string, session: Session) => kv.set(sessionKey(site, sid), JSON.stringify(session), SESSION_TTL);

  async function sessionOf(site: string, req: http.IncomingMessage, res: http.ServerResponse) {
    const name = cookieName(site);
    const sid = new RegExp(`(?:^|;\\s*)${name}=([0-9a-f]{32})`).exec(req.headers.cookie ?? '')?.[1];
    const stored = sid ? await kv.get(sessionKey(site, sid)) : null;
    if (sid && stored) return { sid, session: JSON.parse(stored) as Session };
    const fresh = crypto.randomBytes(16).toString('hex');
    await saveSession(site, fresh, {});
    res.setHeader('set-cookie', `${name}=${fresh}; HttpOnly; SameSite=Lax; Path=/${site.startsWith('https:') ? '; Secure' : ''}`);
    return { sid: fresh, session: {} as Session };
  }

  const json = (res: http.ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json', ...cors });
    res.end(JSON.stringify(body));
  };
  const redirect = (res: http.ServerResponse, location: string) => {
    res.writeHead(303, { location });
    res.end();
  };

  async function handle(site: string, req: http.IncomingMessage, res: http.ServerResponse) {
    const url = new URL(req.url ?? '/', site);
    const challenge = /^\/zkid\/(?:request|response)\/([0-9a-f]{64})$/.exec(url.pathname)?.[1];
    const pendingKey = `zkid:${site}:pend:${challenge}`;

    if (req.method === 'GET' && url.pathname === '/') {
      const { session } = await sessionOf(site, req, res);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(page(site, session));
    }
    if (req.method === 'POST' && url.pathname === '/start') {
      const { sid } = await sessionOf(site, req, res);
      const request = await verifierFor(site).createRequest({ maxAgeSeconds: MAX_AGE });
      await kv.set(`zkid:${site}:pend:${request.challenge}`, JSON.stringify({ request, sid }), REQUEST_TTL + 60);
      await saveSession(site, sid, { challenge: request.challenge });
      return redirect(res, url.searchParams.has('qr') ? '/qr' : holderUrl(site, request.challenge));
    }
    if (req.method === 'GET' && url.pathname === '/qr') {
      const { session } = await sessionOf(site, req, res);
      if (!session.challenge || session.result) return redirect(res, '/');
      const target = holderUrl(site, session.challenge);
      const qr = await QRCode.toDataURL(target, { errorCorrectionLevel: 'M', margin: 4, scale: 6 });
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(qrPage(site, qr, target));
    }
    if (req.method === 'GET' && url.pathname === '/zkid/status') {
      const { session } = await sessionOf(site, req, res);
      return json(res, 200, session.result ? { ...session.result, account: session.account } : null);
    }
    if (req.method === 'GET' && url.pathname === '/sample-qr.png' && testIssuer?.privateKey) {
      const minor = url.searchParams.has('minor');
      const png = await sampleQr(testIssuer.privateKey, minor);
      res.writeHead(200, {
        'content-type': 'image/png',
        'content-disposition': `attachment; filename="zkid-synthetic-test-qr-${minor ? 'under-19' : 'adult'}.png"`,
        'cache-control': 'no-store',
      });
      return res.end(png);
    }
    if (challenge && req.method === 'OPTIONS') {
      res.writeHead(204, cors);
      return res.end();
    }
    if (challenge && req.method === 'GET' && url.pathname.startsWith('/zkid/request/')) {
      const entry = await kv.get(pendingKey);
      if (!entry) return json(res, 404, { error: 'unknown request' });
      const { request } = JSON.parse(entry) as { request: ProofRequest };
      return json(res, 200, { request, responseUrl: `${site}/zkid/response/${challenge}`, returnUrl: `${site}/` });
    }
    if (challenge && req.method === 'POST' && url.pathname.startsWith('/zkid/response/')) {
      const entry = await kv.get(pendingKey);
      if (!entry) return json(res, 404, { ok: false, code: 'CHALLENGE_MISMATCH', detail: 'unknown request' });
      const { request, sid } = JSON.parse(entry) as { request: ProofRequest; sid: string };
      const body = (await readJson(req)) as { proof?: unknown; publicSignals?: unknown };
      const result = await verifierFor(site).verify(body?.proof, body?.publicSignals, request);
      const session: Session = { challenge, result };
      if (result.ok) session.account = await kv.incr(`zkid:${site}:accounts`);
      await saveSession(site, sid, session);
      console.log(`${new Date().toISOString()} ${site} ${result.ok ? `accepted, account #${session.account}` : `refused ${result.code}`}`);
      return json(res, 200, result.ok ? { ok: true, account: session.account } : result);
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  }

  return async function demoApp(req: http.IncomingMessage, res: http.ServerResponse) {
    const site = options.siteFor(req);
    try {
      if (!site) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        return res.end('not a demo shop');
      }
      await handle(site, req, res);
    } catch (err) {
      if (!res.headersSent) json(res, err instanceof BadRequest ? 400 : 500, { error: (err as Error).message });
      else res.end();
    }
  };
}

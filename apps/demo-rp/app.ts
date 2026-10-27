// Demo relying party ("Demo shop"): a page that uses the verifier SDK end to
// end. Each visitor sets the shop's rules for their own visit: 19 or older,
// and gender, PIN code and state, which a proof reveals by value. The shop
// never sees a QR: it issues a request, the holder app proves on the person's
// device, and only the proof comes back. One account per nullifier.
// createDemoApp serves one or more shops, each identified by the origin a
// request arrives on: server.ts runs one locally, vercel/handler.ts several on
// Vercel. The pages are in views.ts.

import crypto from 'node:crypto';
import type http from 'node:http';
import QRCode from 'qrcode';
import { GENDERS, RequestError, checkRules, createVerifier, type ProofRequest, type Rules, type Store } from '../../packages/verifier-sdk/src/index.ts';
import { checkRegistry, productionRegistry, testRegistry, type Registry } from '../../packages/issuer-registry/index.ts';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../../packages/secure-qr/synthetic.mjs';
import type { KV } from './kv.ts';
import { STATES, qrPage, shopPage, type Session } from './views.ts';

const REQUEST_TTL = 15 * 60; // the SDK's default is 5 minutes; on a phone, proving alone can take minutes
const MAX_AGE = 7 * 86400; // a QR generated in the last 7 days
const SESSION_TTL = 86400;
const CODE_TTL = 7 * 86400; // how long a shop remembers a per-site code
const DEFAULT_RULES: Rules = { age19: true };

export interface DemoOptions {
  // The shop's verifier id (its origin) for this request, or null if the request is not for a shop.
  siteFor(req: http.IncomingMessage): string | null;
  holder: string; // the holder app's URL
  registry: Registry;
  kv: KV;
  // The demo's TEST issuer, if the registry trusts one. With its private key, the shops hand out sample QRs.
  testIssuer?: { label: string; privateKey?: crypto.KeyObject };
}

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

async function readBody(req: http.IncomingMessage, limit: number) {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new BadRequest('body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function readJson(req: http.IncomingMessage): Promise<unknown> {
  const body = await readBody(req, 64 * 1024);
  try {
    return JSON.parse(body);
  } catch {
    throw new BadRequest('body is not JSON');
  }
}

// The rules form (views.ts) as rules. checkRules has the last word.
function rulesFrom(form: URLSearchParams): Rules {
  const rules: Rules = { age19: form.get('age19') === 'on' };
  const gender = form.getAll('gender');
  const pinCode = (form.get('pin') ?? '')
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((p) => p.replace(/x+$/i, '')); // 5600xx is the range 5600
  const state = form.getAll('state');
  if (gender.length) rules.gender = gender as Rules['gender'];
  if (pinCode.length) rules.pinCode = pinCode;
  if (state.length) rules.state = state;
  return checkRules(rules);
}

// A synthetic QR, signed by the TEST issuer, as a PNG: an adult born in 1990,
// or someone 17 years old today, with the gender, PIN code and state asked for.
async function sampleQr(privateKey: crypto.KeyObject, params: URLSearchParams) {
  const now = new Date();
  const minor = params.has('minor') || params.get('age') === 'minor';
  const dob = minor ? `${String(now.getUTCDate()).padStart(2, '0')}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${now.getUTCFullYear() - 17}` : '01-01-1990';
  const gender = params.get('gender') ?? 'M';
  const pincode = params.get('pin') ?? '560034';
  const state = params.get('state') ?? 'Karnataka';
  if (!Object.hasOwn(GENDERS, gender)) throw new BadRequest('gender must be M, F or T');
  if (!/^[1-9][0-9]{5}$/.test(pincode)) throw new BadRequest('pin must be six digits, not starting with 0');
  if (!STATES.includes(state)) throw new BadRequest('state must be one of the listed states');
  const { text } = makeSyntheticSecureQr(privateKey, {
    version: 'V5',
    photo: syntheticPhoto(900),
    trailing: unknownTrailer(27),
    fields: { ...syntheticFields({ generatedAt: now }), dob, gender, pincode, state },
  });
  // Numeric mode, as UIDAI's codes; low error correction keeps 3,000+ digits readable.
  const png = await QRCode.toBuffer([{ data: text, mode: 'numeric' }], { errorCorrectionLevel: 'L', margin: 4, scale: 4 });
  return { png, name: `zkid-synthetic-test-qr-${minor ? 'under-19' : 'adult'}-${gender}-${pincode}.png` };
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
  const page = (site: string, session: Session, error?: string) =>
    shopPage({ site, session, rules: session.rules ?? DEFAULT_RULES, testIssuerLabel: testIssuer?.label, samples: !!testIssuer?.privateKey, error });

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
    if (req.method === 'POST' && url.pathname === '/rules') {
      const { sid, session } = await sessionOf(site, req, res);
      let rules: Rules;
      try {
        rules = rulesFrom(new URLSearchParams(await readBody(req, 16 * 1024)));
      } catch (err) {
        if (!(err instanceof RequestError)) throw err;
        res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(page(site, session, `Those rules were not saved: ${err.message.replace(/^INVALID_REQUEST: /, '')}.`));
      }
      await saveSession(site, sid, { ...session, rules });
      return redirect(res, '/');
    }
    if (req.method === 'POST' && url.pathname === '/start') {
      const { sid, session } = await sessionOf(site, req, res);
      const rules = session.rules ?? DEFAULT_RULES;
      const request = await verifierFor(site).createRequest({ maxAgeSeconds: MAX_AGE, rules });
      await kv.set(`zkid:${site}:pend:${request.challenge}`, JSON.stringify({ request, sid }), REQUEST_TTL + 60);
      await saveSession(site, sid, { challenge: request.challenge, rules });
      return redirect(res, url.searchParams.has('qr') ? '/qr' : holderUrl(site, request.challenge));
    }
    if (req.method === 'GET' && url.pathname === '/qr') {
      const { session } = await sessionOf(site, req, res);
      if (!session.challenge || session.result) return redirect(res, '/');
      const target = holderUrl(site, session.challenge);
      const qr = await QRCode.toDataURL(target, { errorCorrectionLevel: 'M', margin: 4, scale: 6 });
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(qrPage(site, session.rules ?? DEFAULT_RULES, qr, target));
    }
    if (req.method === 'GET' && url.pathname === '/zkid/status') {
      const { session } = await sessionOf(site, req, res);
      return json(res, 200, session.result ? { ...session.result, account: session.account } : null);
    }
    if (req.method === 'GET' && url.pathname === '/sample-qr.png' && testIssuer?.privateKey) {
      const { png, name } = await sampleQr(testIssuer.privateKey, url.searchParams);
      res.writeHead(200, { 'content-type': 'image/png', 'content-disposition': `attachment; filename="${name}"`, 'cache-control': 'no-store' });
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
      // Keep rules the visitor saved while the holder was proving.
      const current = JSON.parse((await kv.get(sessionKey(site, sid))) ?? '{}') as Session;
      const session: Session = { challenge, result, rules: current.rules ?? request.rules };
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

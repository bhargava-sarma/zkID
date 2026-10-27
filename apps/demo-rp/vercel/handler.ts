// The hosted demo on Vercel: the holder app and the demo shops, one deployment.
// - The holder's domain, set by ZKID_DEMO_HOLDER, serves the holder app's demo
//   build under /holder/ (static files, so every domain has them; the shops send
//   people to the holder's). Its / redirects there.
// - Every other domain the project answers on is a demo shop (app.ts), whose
//   verifier id is its origin.
// State is in Upstash Redis (KV_REST_API_URL and KV_REST_API_TOKEN, as Vercel's
// integration names them). The demo's TEST issuer key is made by vercel/build.mjs
// on every deployment; only these shops and the holder's demo build trust it.

import crypto from 'node:crypto';
import fs from 'node:fs';
import type http from 'node:http';
import { createDemoApp, demoRegistry } from '../app.ts';
import { UpstashKV } from '../kv.ts';

const env = process.env;
const isLocal = (host: string) => /^localhost(:|$)/.test(host);

// The holder app: https://<its domain>/holder/, http only for localhost. Set, not
// guessed: the project answers on several domains, and any of them could be the
// one Vercel calls its production domain.
function holderUrl(value = '') {
  try {
    const url = new URL(value);
    if (url.protocol === (isLocal(url.host) ? 'http:' : 'https:') && url.pathname === '/holder/' && !url.search && !url.hash) return url;
  } catch {
    /* not a URL */
  }
  return undefined;
}
const holder = holderUrl(env.ZKID_DEMO_HOLDER);
// An empty variable counts as unset.
const kvUrl = env.KV_REST_API_URL || env.UPSTASH_REDIS_REST_URL;
const kvToken = env.KV_REST_API_TOKEN || env.UPSTASH_REDIS_REST_TOKEN;
const missing = [
  !holder && "ZKID_DEMO_HOLDER, as https://<the holder's domain>/holder/",
  !kvUrl && 'KV_REST_API_URL',
  !kvToken && 'KV_REST_API_TOKEN',
].filter(Boolean);

// Written by vercel/build.mjs next to this file: the TEST issuer's public key and private key.
const issuer = JSON.parse(fs.readFileSync(new URL('./demo-issuer.json', import.meta.url), 'utf8')) as {
  keys: { id: string; label: string; modulus: string; keyHash: string }[];
  privateKeyPem: string;
};

const HOST = /^[a-z0-9.-]+(:[0-9]{1,5})?$/i;
const holderHost = holder?.host ?? '';

const app = missing.length
  ? null
  : createDemoApp({
      // http only for localhost, as the SDK requires.
      siteFor: (req) => {
        const host = req.headers.host ?? '';
        if (!HOST.test(host) || host === holderHost) return null;
        return `${isLocal(host) ? 'http' : 'https'}://${host}`;
      },
      holder: holder!.href,
      registry: demoRegistry(issuer.keys),
      kv: new UpstashKV(kvUrl!, kvToken!),
      testIssuer: { label: `zkID's demo TEST issuer (not UIDAI)`, privateKey: crypto.createPrivateKey(issuer.privateKeyPem) },
    });

export default async function handler(req: http.IncomingMessage, res: http.ServerResponse) {
  if (!app) {
    res.writeHead(500, { 'content-type': 'text/plain' });
    return res.end(`The zkID demo is not configured. Set ${missing.join('; ')}. See apps/demo-rp/README.md.`);
  }
  if (req.headers.host === holderHost) {
    if (new URL(req.url ?? '/', 'http://x').pathname === '/') {
      res.writeHead(302, { location: holder!.pathname });
      return res.end();
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    return res.end('not found');
  }
  return app(req, res);
}

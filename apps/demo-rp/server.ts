// The demo shop (app.ts), locally: one shop per process, state in memory
// (THREAT_MODEL S6). vercel/handler.ts runs the hosted demo.
//
// Usage: node server.ts --port 4101 [--holder http://localhost:5173] [--demo]
//   --holder  where the holder app runs (default: the frontend's Vite dev server).
//   --demo    also trusts the local demo's TEST issuer (run setup-demo.mjs first).
//             Without it, only UIDAI's keys from the issuer registry are trusted.
// The verifier id is http://localhost:<port> unless ZKID_VERIFIER_ID is set.

import fs from 'node:fs';
import http from 'node:http';
import { productionRegistry } from '../../packages/issuer-registry/index.ts';
import { createDemoApp, demoRegistry } from './app.ts';
import { MemoryKV } from './kv.ts';

const arg = (name: string) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
};
const port = Number(arg('--port') ?? 4101);
const holder = arg('--holder') ?? 'http://localhost:5173';
const verifierId = process.env.ZKID_VERIFIER_ID ?? `http://localhost:${port}`;
const demo = process.argv.includes('--demo');

const registry = demo
  ? demoRegistry(JSON.parse(fs.readFileSync(new URL('./.demo/test-issuer.json', import.meta.url), 'utf8')).keys)
  : productionRegistry();

const app = createDemoApp({
  siteFor: () => verifierId,
  holder,
  registry,
  kv: new MemoryKV(),
  testIssuer: demo ? { label: 'a local TEST issuer (not UIDAI)' } : undefined,
});

http.createServer(app).listen(port, () => console.log(`demo verifier ${verifierId}${demo ? ' (demo)' : ''}; holder app ${holder}`));

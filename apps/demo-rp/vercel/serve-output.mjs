#!/usr/bin/env node
// Serves a hosted-demo build (.vercel/output, from vercel/build.mjs) locally, as
// Vercel routes it: /holder/ and other static files first, everything else to
// the function. One port per domain: the first is the holder's, the others are
// demo shops.
//
// Usage: node vercel/serve-output.mjs [--output <dir>] [--ports 4100,4101,4102]
// Without KV_REST_API_URL, a stand-in for Upstash's REST API keeps the state in
// memory on the first port + 99. ZKID_DEMO_HOLDER defaults to the first port.

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? fallback : process.argv[i + 1];
};
const output = path.resolve(arg('--output', path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.vercel', 'output')));
const ports = arg('--ports', '4100,4101,4102').split(',').map(Number);
const listen = (server, port) => new Promise((resolve) => server.listen(port, resolve));

// The few Redis commands the demo uses (GET, SET with EX and NX, INCR), as Upstash's REST API takes them.
async function fakeUpstash(port) {
  const data = new Map();
  const live = (key) => {
    const entry = data.get(key);
    if (entry && entry.expires <= Date.now()) data.delete(key);
    return data.get(key);
  };
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    const [command, key, ...rest] = JSON.parse(body);
    let result;
    if (command === 'GET') result = live(key)?.value ?? null;
    else if (command === 'SET') {
      const [value, ...options] = rest;
      const ex = options.indexOf('EX');
      if (options.includes('NX') && live(key)) result = null;
      else {
        data.set(key, { value: String(value), expires: ex === -1 ? Infinity : Date.now() + Number(options[ex + 1]) * 1000 });
        result = 'OK';
      }
    } else if (command === 'INCR') {
      result = Number(live(key)?.value ?? 0) + 1;
      data.set(key, { value: String(result), expires: live(key)?.expires ?? Infinity });
    } else {
      res.writeHead(400, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: `unsupported command ${command}` }));
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ result }));
  });
  await listen(server, port);
  return `http://localhost:${port}`;
}

if (!process.env.KV_REST_API_URL) {
  process.env.KV_REST_API_URL = await fakeUpstash(ports[0] + 99);
  process.env.KV_REST_API_TOKEN = 'local';
}
process.env.ZKID_DEMO_HOLDER ||= `http://localhost:${ports[0]}/holder/`;

const func = path.join(output, 'functions', 'index.func');
const { handler } = JSON.parse(fs.readFileSync(path.join(func, '.vc-config.json'), 'utf8'));
const { default: fn } = await import(pathToFileURL(path.join(func, handler)).href);

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.wasm': 'application/wasm' };
const staticRoot = path.join(output, 'static');
function staticFile(pathname) {
  if (/^\/holder\/?$/.test(pathname)) return path.join(staticRoot, 'holder', 'index.html');
  const file = path.join(staticRoot, path.normalize(decodeURIComponent(pathname)));
  return file.startsWith(staticRoot + path.sep) && fs.existsSync(file) && fs.statSync(file).isFile() ? file : null;
}

for (const port of ports) {
  const server = http.createServer((req, res) => {
    const file = staticFile(new URL(req.url ?? '/', 'http://x').pathname);
    if (!file) return fn(req, res);
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] ?? 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  await listen(server, port);
}
console.log(`hosted demo: holder ${process.env.ZKID_DEMO_HOLDER}, shops ${ports.slice(1).map((p) => `http://localhost:${p}`).join(', ')}`);

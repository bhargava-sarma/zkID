#!/usr/bin/env node
// Downloads Anon Aadhaar's published v2.0.0 circuit artifacts into artifacts/
// and checks each against the SHA-256 in artifacts.json. A file that does not
// match is deleted, never used. Same pattern as v1's fetch_artifacts.js.
//
// Usage: node fetch-artifacts.mjs [name ...]   (default: all three files)
// AA_ARTIFACTS_URL overrides the release URL.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { DEFAULT_DIR, MANIFEST, checkedArtifact } from './index.mjs';

const baseUrl = process.env.AA_ARTIFACTS_URL || MANIFEST.release;
const wanted = process.argv.slice(2);
const unknown = wanted.filter((name) => !MANIFEST.files.some((f) => f.name === name));
if (unknown.length) {
  console.error(`Unknown artifact: ${unknown.join(', ')}. Known: ${MANIFEST.files.map((f) => f.name).join(', ')}`);
  process.exit(2);
}

async function download(entry, dest) {
  const res = await fetch(`${baseUrl}/${entry.name}`);
  if (!res.ok) throw new Error(`${entry.name}: HTTP ${res.status} from ${baseUrl}`);
  const tmp = `${dest}.download`;
  const hash = crypto.createHash('sha256');
  const out = fs.createWriteStream(tmp);
  let received = 0;
  let lastPct = -1;
  for await (const chunk of Readable.fromWeb(res.body)) {
    hash.update(chunk);
    received += chunk.length;
    if (!out.write(chunk)) await new Promise((r) => out.once('drain', r));
    const pct = Math.floor((received / entry.bytes) * 100);
    if (entry.bytes > 10e6 && pct % 10 === 0 && pct !== lastPct) {
      lastPct = pct;
      process.stdout.write(`\r  ${entry.name}: ${pct}%`);
    }
  }
  await new Promise((resolve, reject) => out.end((err) => (err ? reject(err) : resolve())));
  if (entry.bytes > 10e6) process.stdout.write('\n');

  // Only a verified file replaces the destination.
  const digest = hash.digest('hex');
  if (digest !== entry.sha256) {
    fs.rmSync(tmp, { force: true });
    throw new Error(`${entry.name}: checksum mismatch (got ${digest})`);
  }
  fs.renameSync(tmp, dest);
}

try {
  fs.mkdirSync(DEFAULT_DIR, { recursive: true });
  for (const entry of MANIFEST.files.filter((f) => !wanted.length || wanted.includes(f.name))) {
    const dest = path.join(DEFAULT_DIR, entry.name);
    if (fs.existsSync(dest)) {
      try {
        await checkedArtifact(entry.name);
        console.log(`ok       ${entry.name}`);
        continue;
      } catch {
        fs.rmSync(dest);
      }
    }
    console.log(`fetching ${entry.name} (${(entry.bytes / 1e6).toFixed(1)} MB)`);
    await download(entry, dest);
    console.log(`ok       ${entry.name}`);
  }
  console.log('Circuit artifacts ready.');
} catch (err) {
  console.error(`[FETCH] ${err.message}`);
  process.exit(1);
}

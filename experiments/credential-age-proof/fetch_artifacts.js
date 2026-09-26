#!/usr/bin/env node
// Downloads the credential circuit's proving artifacts from the GitHub release
// and checks each against the SHA-256 in artifacts.json. These are the exact
// files the deployed CredentialAgeVerifier was generated from.
// ZKID_ARTIFACTS_URL overrides the release URL.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');

const manifest = require('./artifacts.json');
const baseUrl = process.env.ZKID_ARTIFACTS_URL || manifest.release;

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', (d) => hash.update(d)).on('end', () => resolve(hash.digest('hex'))).on('error', reject);
  });
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

(async () => {
  for (const entry of manifest.files) {
    const dest = path.join(__dirname, entry.path);
    if (fs.existsSync(dest) && (await sha256File(dest)) === entry.sha256) {
      console.log(`ok       ${entry.path}`);
      continue;
    }
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    console.log(`fetching ${entry.path} (${(entry.bytes / 1e6).toFixed(1)} MB)`);
    await download(entry, dest);
    console.log(`ok       ${entry.path}`);
  }
  console.log('Credential circuit artifacts ready.');
})().catch((err) => {
  console.error(`[FETCH] ${err.message}`);
  process.exit(1);
});

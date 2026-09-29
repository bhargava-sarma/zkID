#!/usr/bin/env node
// Puts both credential circuits' artifacts in public/circuit/ for the browser prover.
// Proving keys are split into 20 MB parts so any static host can serve them.
// Uses local copies when present, otherwise the GitHub releases; checks SHA-256 either way.
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = path.join(here, '..', '..', 'backend', 'circuits');
const CIRCUITS = ['credential-age-proof', 'credential-match-proof'];
const OUT = path.join(here, '..', 'public', 'circuit');
const MANIFEST = path.join(OUT, 'manifest.json');
const PART_BYTES = 20 * 1024 * 1024;

// Every artifact of every circuit, with the directory and release it comes from.
const entries = CIRCUITS.flatMap((circuit) => {
  const dir = path.join(CIRCUITS_DIR, circuit);
  const release = JSON.parse(fs.readFileSync(path.join(dir, 'artifacts.json'), 'utf8'));
  return release.files.map((file) => ({ ...file, dir, release: release.release }));
});
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function upToDate() {
  if (!fs.existsSync(MANIFEST)) return false;
  const { files } = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  return entries.every((r) =>
    files.some((f) => f.sha256 === r.sha256 && f.parts.every((p) => fs.existsSync(path.join(OUT, p))))
  );
}

async function load(entry) {
  const local = path.join(entry.dir, entry.path);
  if (fs.existsSync(local)) {
    const data = fs.readFileSync(local);
    if (sha256(data) === entry.sha256) return data;
  }
  console.log(`[circuit] downloading ${entry.name} (${(entry.bytes / 1e6).toFixed(1)} MB)`);
  const res = await fetch(`${entry.release}/${entry.name}`);
  if (!res.ok) throw new Error(`${entry.name}: HTTP ${res.status}`);
  const data = Buffer.from(await res.arrayBuffer());
  if (sha256(data) !== entry.sha256) throw new Error(`${entry.name}: checksum mismatch`);
  return data;
}

if (upToDate()) {
  console.log('[circuit] up to date');
} else {
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });
  const files = [];
  for (const entry of entries) {
    const data = await load(entry);
    const parts = [];
    for (let offset = 0; offset < data.length; offset += PART_BYTES) {
      const name = data.length > PART_BYTES ? `${entry.name}.${String(parts.length).padStart(2, '0')}` : entry.name;
      fs.writeFileSync(path.join(OUT, name), data.subarray(offset, offset + PART_BYTES));
      parts.push(name);
    }
    files.push({ name: entry.name, bytes: entry.bytes, sha256: entry.sha256, parts });
  }
  fs.writeFileSync(MANIFEST, JSON.stringify({ files }, null, 2) + '\n');
  console.log(`[circuit] ready: ${files.map((f) => `${f.name} (${f.parts.length} part${f.parts.length > 1 ? 's' : ''})`).join(', ')}`);
}

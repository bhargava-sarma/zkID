#!/usr/bin/env node
// Saves UIDAI's official sample Secure QR (V1) to local/ (gitignored). The
// sample was published on UIDAI's QR code reader page; this takes the copy in
// Anon Aadhaar's repository at a pinned commit, because uidai.gov.in is not
// reachable from every network. It holds a sample resident's details, so it is
// never committed.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const COMMIT = '4dad918761cfb1d7d5ed9918dcd796d0cb23ae82';
const URL = `https://raw.githubusercontent.com/anon-aadhaar/anon-aadhaar/${COMMIT}/packages/circuits/scripts/generateTestData.ts`;
const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'local', 'uidai-official-sample-v1.txt');

const res = await fetch(URL);
if (!res.ok) throw new Error(`HTTP ${res.status} from ${URL}`);
const match = (await res.text()).match(/const data =\s*'([0-9]+)'/);
if (!match) throw new Error('No sample QR string found in the source file.');

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${match[1]}\n`);
console.log(`wrote ${path.relative(process.cwd(), OUT)}: ${match[1].length} digits, sha256 ${crypto.createHash('sha256').update(match[1]).digest('hex')}`);

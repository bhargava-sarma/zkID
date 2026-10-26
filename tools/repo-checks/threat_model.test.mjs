// Checks docs/THREAT_MODEL.md against Phase 2's acceptance rule: every goal
// maps to at least one planned test, and the tables cite only tests that exist.
// Run: node --test "tools/repo-checks/*.test.mjs"
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DOC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'docs', 'THREAT_MODEL.md');
const GOALS = ['G1', 'G2', 'G3', 'G4', 'G5', 'G6'];
const ADVERSARIES = ['A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7'];

// "T1.1–T1.3, T2.5" -> T1.1, T1.2, T1.3, T2.5
function testIds(cell) {
  const ids = [];
  for (const [, major, from, to] of cell.matchAll(/T(\d)\.(\d+)(?:\s*[–-]\s*T\1\.(\d+))?/g)) {
    for (let n = Number(from); n <= Number(to ?? from); n++) ids.push(`T${major}.${n}`);
  }
  return ids;
}

// Table rows whose first cell matches `first`, as arrays of trimmed cells.
const rows = (markdown, first) =>
  markdown
    .split('\n')
    .filter((line) => first.test(line))
    .map((line) => line.split('|').slice(1, -1).map((cell) => cell.trim()));

export function problems(markdown) {
  const found = [];
  const defined = new Set(rows(markdown, /^\| T\d\.\d+ \|/).map((row) => row[0]));
  const goals = rows(markdown, /^\| G\d /);
  const attacks = rows(markdown, /^\| A\d\.\d+ \|/);
  const cited = new Set();

  for (const goal of GOALS) {
    const ids = testIds(goals.find((row) => row[0].startsWith(`${goal} `))?.at(-1) ?? '');
    if (!ids.length) found.push(`${goal} maps to no test`);
    for (const id of ids) {
      cited.add(id);
      if (!defined.has(id)) found.push(`${goal} cites undefined ${id}`);
    }
  }
  for (const id of defined) if (!cited.has(id)) found.push(`${id} serves no goal`);

  for (const [id, , defended, , tests] of attacks) {
    if (!/^(Yes|Partly|No)\b/.test(defended.replace(/\*/g, ''))) found.push(`${id}: "Defended?" is not Yes, Partly or No`);
    for (const test of testIds(tests)) if (!defined.has(test)) found.push(`${id} cites undefined ${test}`);
  }
  for (const adversary of ADVERSARIES) {
    if (!attacks.some(([id]) => id.startsWith(`${adversary}.`))) found.push(`no attack row for ${adversary}`);
  }
  if (!attacks.some(([, , defended]) => defended.replace(/\*/g, '').startsWith('No'))) found.push('no attack is marked not defended');
  return found;
}

const doc = fs.readFileSync(DOC, 'utf8');
const line = (prefix) => doc.split('\n').find((l) => l.startsWith(prefix));

test('THREAT_MODEL.md: every goal maps to a defined test, and every test to a goal', () => {
  assert.deepEqual(problems(doc), []);
});

test('negative control: missing, undefined and unclassified entries are reported', () => {
  const g6 = line('| G6 ');
  assert.ok(problems(doc.replace(g6, g6.replace(/T\d\.\d+/g, 'none'))).includes('G6 maps to no test'));

  const t63 = line('| T6.3 |');
  assert.ok(problems(doc.replace(t63, t63.replace('T6.3', 'T9.9'))).includes('G6 cites undefined T6.3'));

  const a25 = line('| A2.5 |');
  assert.ok(problems(doc.replace(a25, a25.replace('**No**', 'Maybe'))).includes('A2.5: "Defended?" is not Yes, Partly or No'));

  const a7 = doc.split('\n').filter((l) => l.startsWith('| A7.'));
  assert.ok(problems(a7.reduce((text, l) => text.replace(`${l}\n`, ''), doc)).includes('no attack row for A7'));
});

#!/usr/bin/env node
// Runs every suite whose tests docs/THREAT_MODEL.md cites, then writes
// docs/ATTACK_REPORT.md from the results: each attack, the threat model's
// verdict on it, and the tests that check it, all of which must have passed.
//
// Exits 1, writing nothing, if a suite fails, a test fails, a cited test is
// skipped or did not run, or a test names an id the threat model lacks. To
// change the report, change THREAT_MODEL.md or the tests and rerun.
//
// Needs every suite installed, the circuit artifacts (packages/circuit:
// npm run fetch) and Playwright's Chromium for the end-to-end test.
// Usage: node attack-suite/report.mjs   (from anywhere)

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const THREAT_MODEL = path.join(ROOT, 'docs', 'THREAT_MODEL.md');
const REPORT = path.join(ROOT, 'docs', 'ATTACK_REPORT.md');
const REPORTER = path.join(ROOT, 'attack-suite', 'reporter.mjs');

// Every suite with tests the threat model cites, in the order they run.
const SUITES = [
  { dir: 'packages/secure-qr', tests: ['test/*.test.mjs'] },
  { dir: 'packages/circuit', tests: ['test/*.test.mjs'] },
  { dir: 'packages/issuer-registry', tests: ['test/*.test.ts'] },
  { dir: 'packages/verifier-sdk', tests: ['test/*.test.ts'] },
  { dir: 'frontend', tests: ['src/holder/*.test.js'] },
  { dir: 'apps/demo-rp', tests: ['e2e/*.test.ts'], flags: ['--test-concurrency=1'] },
  { dir: 'attack-suite', tests: ['test/*.test.ts'] },
];

// ---- The threat model -----------------------------------------------------------------

// Table rows whose first cell matches `first`, as arrays of trimmed cells.
const rows = (markdown, first) =>
  markdown
    .split('\n')
    .filter((line) => first.test(line))
    .map((line) => line.split('|').slice(1, -1).map((cell) => cell.trim()));

// "T1.1–T1.3, T2.5" -> T1.1, T1.2, T1.3, T2.5
function testIds(cell) {
  const ids = [];
  for (const [, major, from, to] of cell.matchAll(/T(\d)\.(\d+)(?:\s*[–-]\s*T\1\.(\d+))?/g)) {
    for (let n = Number(from); n <= Number(to ?? from); n++) ids.push(`T${major}.${n}`);
  }
  return ids;
}

function verdict(cell) {
  const text = cell.replace(/\*/g, '');
  const kind = ['Yes', 'Partly', 'No'].find((word) => new RegExp(`^${word}\\b`).test(text));
  if (!kind) throw new Error(`"Defended?" must start with Yes, Partly or No: ${cell}`);
  return kind;
}

function threatModel() {
  const markdown = fs.readFileSync(THREAT_MODEL, 'utf8');
  const adversaries = rows(markdown, /^\| A\d+ \|/).map(([id, name]) => ({ id, name }));
  const attacks = rows(markdown, /^\| A\d+\.\d+ \|/).map(([id, attack, defended, mechanism, tests]) => ({
    id,
    attack,
    defended,
    kind: verdict(defended),
    mechanism,
    tests: testIds(tests),
  }));
  const tests = new Map(rows(markdown, /^\| T\d+\.\d+ \|/).map(([id, , input, expected]) => [id, { input, expected }]));
  return { adversaries, attacks, tests };
}

// ---- The run ---------------------------------------------------------------------------

// Ids a test name starts with: "T2.2, T2.3: ..." or "T2.1 (Phase 4 acceptance): ...".
const leadingIds = (name) => testIds(/^T\d+\.\d+(?:,\s*T\d+\.\d+)*/.exec(name)?.[0] ?? '');

function runSuites() {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'zkid-attack-report-'));
  const results = [];
  const problems = [];
  try {
    for (const [i, suite] of SUITES.entries()) {
      const jsonl = path.join(out, `${i}.jsonl`);
      console.log(`\n=== ${suite.dir} ===`);
      const run = spawnSync(
        process.execPath,
        ['--test', ...(suite.flags ?? []), '--test-reporter=spec', '--test-reporter-destination=stdout', `--test-reporter=${REPORTER}`, `--test-reporter-destination=${jsonl}`, ...suite.tests],
        { cwd: path.join(ROOT, suite.dir), stdio: 'inherit' },
      );
      if (run.status !== 0) problems.push(`${suite.dir}: the suite exited with ${run.status ?? run.signal}`);
      const lines = fs.existsSync(jsonl) ? fs.readFileSync(jsonl, 'utf8').split('\n').filter(Boolean) : [];
      if (!lines.length) problems.push(`${suite.dir}: no test ran`);
      for (const line of lines) results.push({ suite: suite.dir, ...JSON.parse(line) });
    }
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
  return { results, problems };
}

// ---- The report ------------------------------------------------------------------------

const cell = (text) => text.replace(/\|/g, '\\|');

function render({ adversaries, attacks, tests }, passed) {
  const byKind = (list, kind) => list.filter((a) => a.kind === kind).length;
  const ran = [...passed.keys()].sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
  // Sorted, because node:test reports files in the order they finish.
  const suiteIndex = (r) => SUITES.findIndex((s) => s.dir === r.suite);
  const namesOf = (id) =>
    [...passed.get(id)]
      .sort((a, b) => suiteIndex(a) - suiteIndex(b) || a.name.localeCompare(b.name, 'en'))
      .map((r) => `\`${r.suite}\`: ${cell(r.name)}`)
      .join('<br>');
  const testList = (ids) => (ids.length ? ids.map((id) => `${id} ✓`).join(', ') : 'none');
  const lines = [
    '# Attack report',
    '',
    '<!-- Generated by attack-suite/report.mjs from a test run. Do not edit: change docs/THREAT_MODEL.md or the tests, then rerun it. -->',
    '',
    `Every attack in [THREAT_MODEL.md](THREAT_MODEL.md) (section 5), its verdict there, and the tests that check it. ` +
      `This file is written only when no test in the ${SUITES.length} suites below fails and every test the threat model cites passes, so each ✓ is a test that passed in that run. ` +
      `For a **No** or Partly row, the tests show the attack succeeding, and where the verdict is qualified, also where it stops.`,
    '',
    `Suites: ${SUITES.map((s) => `\`${s.dir}\``).join(', ')}. Every QR in the tests below is synthetic and signed with an ephemeral test key. ` +
      `Where a test makes a proof, it is a real Groth16 proof under Anon Aadhaar's published proving key.`,
    '',
    '## Summary',
    '',
    '| Adversary | Attacks | Defended | Partly | Not defended |',
    '|---|---|---|---|---|',
    ...adversaries.map(({ id, name }) => {
      const mine = attacks.filter((a) => a.id.startsWith(`${id}.`));
      return `| ${id} ${name} | ${mine.length} | ${byKind(mine, 'Yes')} | ${byKind(mine, 'Partly')} | ${byKind(mine, 'No')} |`;
    }),
    `| **All** | ${attacks.length} | ${byKind(attacks, 'Yes')} | ${byKind(attacks, 'Partly')} | ${byKind(attacks, 'No')} |`,
    '',
    '## Not defended, or only partly',
    '',
    '| | Attack | Verdict | Why | Tests |',
    '|---|---|---|---|---|',
    ...attacks.filter((a) => a.kind !== 'Yes').map((a) => `| ${a.id} | ${cell(a.attack)} | ${cell(a.defended)} | ${cell(a.mechanism)} | ${testList(a.tests)} |`),
    '',
  ];
  for (const { id, name } of adversaries) {
    lines.push(`## ${id} ${name}`, '', '| | Attack | Defended? | How, or why not | Tests |', '|---|---|---|---|---|');
    for (const a of attacks.filter((x) => x.id.startsWith(`${id}.`))) {
      lines.push(`| ${a.id} | ${cell(a.attack)} | ${cell(a.defended)} | ${cell(a.mechanism)} | ${testList(a.tests)} |`);
    }
    lines.push('');
  }
  lines.push('## Tests', '', 'Each id with the tests that passed for it.', '', '| Test | Input | Expected | Passed |', '|---|---|---|---|');
  for (const id of ran) lines.push(`| ${id} | ${cell(tests.get(id).input)} | ${cell(tests.get(id).expected)} | ${namesOf(id)} |`);
  lines.push('');
  return `${lines.join('\n')}\n`.replace(/\n\n$/, '\n');
}

// ---- Main ------------------------------------------------------------------------------

const model = threatModel();
const { results, problems } = runSuites();

const passed = new Map();
for (const r of results) {
  const ids = leadingIds(r.name);
  if (r.outcome === 'fail') problems.push(`${r.suite}: failed: ${r.name}`);
  if (ids.length && r.outcome !== 'pass') problems.push(`${r.suite}: ${r.outcome}: ${r.name}`);
  for (const id of ids) {
    if (!model.tests.has(id)) problems.push(`${r.suite}: "${r.name}" names ${id}, which THREAT_MODEL.md does not define`);
    else if (r.outcome === 'pass') passed.set(id, [...(passed.get(id) ?? []), r]);
  }
}
for (const id of new Set(model.attacks.flatMap((a) => a.tests))) {
  if (!passed.has(id)) problems.push(`${id}: cited by the threat model, but no test for it passed`);
}

if (problems.length) {
  console.error(`\nATTACK REPORT NOT WRITTEN. ${problems.length} problem(s):\n${problems.map((p) => `  - ${p}`).join('\n')}`);
  process.exit(1);
}
fs.writeFileSync(REPORT, render(model, passed));
const count = (kind) => model.attacks.filter((a) => a.kind === kind).length;
console.log(
  `\nWrote ${path.relative(process.cwd(), REPORT)}: ${model.attacks.length} attacks (${count('Yes')} defended, ${count('Partly')} partly, ${count('No')} not), ` +
    `${passed.size} test ids, ${results.filter((r) => r.outcome === 'pass').length} tests passed.`,
);

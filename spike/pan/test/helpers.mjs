// Witness generation for the spike's circuits, and their builds.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import * as snarkjs from 'snarkjs';

export const SPIKE = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
export const BUILD = path.join(SPIKE, 'build');

// Compiles circuits/<name>.circom (or test/circuits/) to build/, once per run.
export function compile(file) {
  const name = path.basename(file, '.circom');
  const wasm = path.join(BUILD, `${name}_js`, `${name}.wasm`);
  if (!fs.existsSync(wasm) || fs.statSync(wasm).mtimeMs < fs.statSync(file).mtimeMs) {
    execFileSync('circom', [file, '--wasm', '-l', path.join(SPIKE, 'node_modules'), '-o', BUILD], { stdio: 'pipe' });
  }
  return wasm;
}

// All the witness's values; witness[1..] begins with the outputs.
export async function witness(wasm, input) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkid-pan-'));
  const file = path.join(dir, 'w.wtns');
  try {
    await snarkjs.wtns.calculate(input, wasm, file);
    return (await snarkjs.wtns.exportJson(file)).map(String);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export async function close() {
  await globalThis.curve_bn128?.terminate();
}

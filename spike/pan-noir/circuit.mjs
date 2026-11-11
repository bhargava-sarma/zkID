// The compiled circuit: circuit/ compiled with noir_wasm into build/program.json
// (gitignored), again only when a source changed.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile, createFileManager } from '@noir-lang/noir_wasm';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const BUILD = path.join(HERE, 'build');
const OUT = path.join(BUILD, 'program.json');

export async function program() {
  const dir = path.join(HERE, 'circuit');
  const sources = [path.join(dir, 'Nargo.toml'), ...fs.readdirSync(path.join(dir, 'src')).map((f) => path.join(dir, 'src', f))];
  const newest = Math.max(...sources.map((f) => fs.statSync(f).mtimeMs));
  if (fs.existsSync(OUT) && fs.statSync(OUT).mtimeMs >= newest) return JSON.parse(fs.readFileSync(OUT, 'utf8'));
  const { program: compiled } = await compile(createFileManager(dir));
  fs.mkdirSync(BUILD, { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(compiled));
  return compiled;
}

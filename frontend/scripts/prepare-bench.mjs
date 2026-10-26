#!/usr/bin/env node
// Copies snarkjs's browser build next to the benchmark page (public/bench/).
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const from = path.join(here, '..', 'node_modules', 'snarkjs', 'build', 'snarkjs.min.js');
const to = path.join(here, '..', 'public', 'bench', 'snarkjs.min.js');
fs.copyFileSync(from, to);
console.log('[bench] snarkjs.min.js ready');

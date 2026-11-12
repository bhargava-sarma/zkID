import fs from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The demo mode (npm run dev:demo, npm run build:demo) also trusts the local
// demo's TEST issuer key, which apps/demo-rp/setup-demo.mjs writes, or the one in
// ZKID_DEMO_ISSUER_FILE (the hosted demo's build sets it). The key is compiled
// in, so every other build contains no test key at all (THREAT_MODEL A1.4).
function demoKeys(mode) {
  if (mode !== 'demo') return null;
  const file = process.env.ZKID_DEMO_ISSUER_FILE ?? new URL('../apps/demo-rp/.demo/test-issuer.json', import.meta.url);
  if (!fs.existsSync(file)) {
    throw new Error(`Demo mode, but ${file} is missing: run \`npm run setup\` in apps/demo-rp first.`);
  }
  return JSON.parse(fs.readFileSync(file, 'utf8')).keys;
}

// Cross-origin isolation lets the PAN prover use several threads
// (SharedArrayBuffer). The hosted builds send the same headers (vercel.json,
// apps/demo-rp/vercel/build.mjs).
const ISOLATION = { 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp' };

// The PAN prover's packages ship WebAssembly that Vite must not pre-bundle.
const NOIR = ['@aztec/bb.js', '@noir-lang/noir_js', '@noir-lang/acvm_js', '@noir-lang/noirc_abi'];

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: { __ZKID_DEMO_KEYS__: JSON.stringify(demoKeys(mode)) },
  worker: { format: 'es' },
  build: { target: 'esnext' },
  // Pre-bundle lazily imported dependencies so dev doesn't reload mid-proof.
  optimizeDeps: { include: ['snarkjs', 'jsqr', 'poseidon-lite', '@xmldom/xmldom', '@zkpassport/poseidon2'], exclude: NOIR, esbuildOptions: { target: 'esnext' } },
  // The app imports code shared with the verifier from ../packages. Their
  // dependencies resolve from this package, the only one a deployment installs.
  resolve: { dedupe: ['poseidon-lite', '@xmldom/xmldom', '@zkpassport/poseidon2', ...NOIR] },
  server: { port: 5173, fs: { allow: ['..'] }, headers: ISOLATION },
  preview: { headers: ISOLATION },
}));

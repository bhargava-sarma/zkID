import fs from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The demo mode (npm run dev:demo, npm run build:demo) also trusts the local
// demo's TEST issuer key, which apps/demo-rp/setup-demo.mjs writes. The key is
// compiled in, so every other build contains no test key at all (THREAT_MODEL A1.4).
function demoKeys(mode) {
  if (mode !== 'demo') return null;
  const file = new URL('../apps/demo-rp/.demo/test-issuer.json', import.meta.url);
  if (!fs.existsSync(file)) {
    throw new Error('Demo mode, but apps/demo-rp/.demo/test-issuer.json is missing: run `npm run setup` in apps/demo-rp first.');
  }
  return JSON.parse(fs.readFileSync(file, 'utf8')).keys;
}

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: { __ZKID_DEMO_KEYS__: JSON.stringify(demoKeys(mode)) },
  worker: { format: 'es' },
  // Pre-bundle lazily imported dependencies so dev doesn't reload mid-proof.
  optimizeDeps: { include: ['snarkjs', 'jsqr', 'poseidon-lite'] },
  // The app imports code shared with the verifier from ../packages. Their
  // dependencies resolve from this package, the only one a deployment installs.
  resolve: { dedupe: ['poseidon-lite'] },
  server: { port: 5173, fs: { allow: ['..'] } },
}));

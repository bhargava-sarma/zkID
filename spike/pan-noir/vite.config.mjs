// Builds the browser test page (web/) into build/web/, with relative paths so
// it can be served from any folder.
import { defineConfig } from 'vite';

export default defineConfig({
  root: 'web',
  base: './',
  publicDir: '../build/web-public',
  build: { outDir: '../build/web', emptyOutDir: true, target: 'esnext' },
  optimizeDeps: {
    exclude: ['@aztec/bb.js', '@noir-lang/noir_js', '@noir-lang/acvm_js', '@noir-lang/noirc_abi'],
    esbuildOptions: { target: 'esnext' },
  },
  worker: { format: 'es' },
});

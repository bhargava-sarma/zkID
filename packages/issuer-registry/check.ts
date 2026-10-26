// Checks a registry file before a build ships it. With --production, any test
// key fails the check (exit 1); a compromised key always does.
// Usage: node check.ts <registry.json> [--production]

import { RegistryError, checkRegistry, type IssuerKey } from './index.ts';
import fs from 'node:fs';

const file = process.argv[2];
const production = process.argv.includes('--production');
if (!file) {
  console.error('Usage: node check.ts <registry.json> [--production]');
  process.exit(2);
}
try {
  const { keys } = JSON.parse(fs.readFileSync(file, 'utf8')) as { keys: IssuerKey[] };
  checkRegistry({ production, keys });
  console.log(`ok: ${keys.length} keys${production ? ', no test keys' : ''}, none compromised`);
} catch (err) {
  console.error(err instanceof RegistryError ? err.message : `cannot read ${file}: ${(err as Error).message}`);
  process.exit(1);
}

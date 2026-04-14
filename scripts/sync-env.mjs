import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const sourceEnv = resolve(root, '.env');
const targetEnv = resolve(root, 'frontend', '.env.local');

if (existsSync(sourceEnv)) {
  mkdirSync(dirname(targetEnv), { recursive: true });
  copyFileSync(sourceEnv, targetEnv);
  console.log(`Synced ${sourceEnv} -> ${targetEnv}`);
} else {
  console.log(`No root .env found at ${sourceEnv}; skipping env sync.`);
}

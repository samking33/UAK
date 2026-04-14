import { spawn } from 'node:child_process';
import { existsSync, copyFileSync, mkdirSync } from 'node:fs';
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

const script = process.argv[2] || 'dev';
const child = spawn(
  'npm',
  ['--prefix', 'frontend', 'run', script],
  {
    cwd: root,
    stdio: 'inherit',
    env: {
      ...process.env,
      UAK_DATA_DIR: resolve(root, '.uak-data'),
    },
  }
);

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});

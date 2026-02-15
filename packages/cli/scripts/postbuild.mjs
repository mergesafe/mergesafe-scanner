import { chmodSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'win32') {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const binPath = path.resolve(here, '..', 'dist', 'index.js');
  chmodSync(binPath, 0o755);
}

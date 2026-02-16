import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const cliRoot = path.resolve(here, '..');
const distDir = path.join(cliRoot, 'dist');
const distIndex = path.join(distDir, 'index.js');

if (fs.existsSync(distIndex) && process.platform !== 'win32') {
  fs.chmodSync(distIndex, 0o755);
}

const semgrepRulesSrc = path.resolve(cliRoot, '../engines/semgrep-rules');
const semgrepRulesDest = path.join(distDir, 'semgrep-rules');
if (fs.existsSync(semgrepRulesSrc)) {
  fs.cpSync(semgrepRulesSrc, semgrepRulesDest, { recursive: true });
}

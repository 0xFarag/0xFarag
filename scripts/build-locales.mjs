// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const script = fileURLToPath(new URL('./build_locales.py', import.meta.url));
const python = process.platform === 'win32' ? 'python' : 'python3';
const run = spawnSync(python, [script, ...process.argv.slice(2)], {stdio: 'inherit'});
if (run.error) throw run.error;
process.exitCode = run.status ?? 1;

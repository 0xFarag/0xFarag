// © Nasser Aldin Farag (0xFarag). All rights reserved.
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { lstat, mkdir, readFile, readdir, rename, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const root = fileURLToPath(new URL('../public/downloads/', import.meta.url));
const { releases } = JSON.parse(await readFile(new URL('./download-releases.json', import.meta.url)));
const checkOnly = process.argv[2] === '--check';
if (process.argv.length !== (checkOnly ? 3 : 2)) throw Error('Usage: node scripts/build-downloads.mjs [--check]');

async function validFile(file, asset) {
  let stat;
  try { stat = await lstat(file); }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  if (!stat.isFile()) throw Error('Expected a regular file: ' + file);
  if (stat.size !== asset.bytes) return false;
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex') === asset.sha256;
}

async function readAsset(tag, asset, temp) {
  const url = 'https://github.com/0xFarag/0xFarag/releases/download/' + tag + '/' + asset.name;
  const options = {redirect: 'manual', signal: AbortSignal.timeout(120_000)};
  let response = await fetch(url, options);
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    const location = new URL(response.headers.get('location'), url);
    await response.body?.cancel();
    if (location.origin !== 'https://release-assets.githubusercontent.com' || location.username || location.password)
      throw Error('Unexpected release asset origin');
    response = await fetch(location, options);
  }
  if (response.status !== 200 || !response.body) {
    await response.body?.cancel();
    throw Error('HTTP ' + response.status + ' for ' + asset.name);
  }
  let bytes = 0;
  const hash = createHash('sha256');
  const verify = new Transform({transform(chunk, encoding, done) {
    bytes += chunk.length;
    if (bytes > asset.bytes) return done(Error('File too large: ' + asset.name));
    hash.update(chunk);
    done(null, chunk);
  }});
  await pipeline(response.body, verify, createWriteStream(temp, {flags: 'wx', mode: 0o644}));
  if (bytes !== asset.bytes || hash.digest('hex') !== asset.sha256)
    throw Error('Release file failed verification: ' + asset.name);
}

for (const release of releases) {
  if (!/^recipient-[a-z]+-preview-[0-9]+$/.test(release.directory) || !/^recipient-[a-z]+-[0-9.]+-preview\.[0-9]+$/.test(release.tag))
    throw Error('Invalid release identity');
  const dir = path.join(root, release.directory);
  if (!checkOnly) await mkdir(dir, {recursive:true});
  if (!(await lstat(dir)).isDirectory()) throw Error('Expected a download directory');
  const names = new Set();
  for (const asset of release.assets) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]+$/.test(asset.name) || !/^[a-f0-9]{64}$/.test(asset.sha256) ||
        !Number.isSafeInteger(asset.bytes) || asset.bytes < 1 || names.has(asset.name))
      throw Error('Invalid release asset metadata');
    names.add(asset.name);
    const file = path.join(dir, asset.name);
    if (await validFile(file, asset)) continue;
    if (checkOnly) throw Error('Missing or invalid release file: ' + asset.name);
    const temp = path.join(dir, '.' + randomUUID() + '.part');
    try {
      await readAsset(release.tag, asset, temp);
      await rename(temp, file);
    } finally {
      await rm(temp, {force:true});
    }
  }
  const entries = await readdir(dir);
  if (entries.length !== names.size || entries.some(name => !names.has(name)))
    throw Error('Unexpected content in ' + release.directory);
  console.log('Verified ' + names.size + ' files for ' + release.tag);
}

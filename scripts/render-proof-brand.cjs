// © Nasser Aldin Farag (0xFarag). All rights reserved.
// Keep this entry point for existing packaging callers. The approved artwork is
// versioned as finished PNGs. Never recreate it from the personal 0xFarag mark.
const {readFile, writeFile} = require('node:fs/promises');
const {createHash} = require('node:crypto');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const fingerprints = {
  icon: '7d769a4fb44fe1bcf265310a91d5f691f393b3585e3692ea8277b968d620f4b8',
  touch: '0c0a965de3719a1082d8624e349f38cedf7a289035e2bde3155c97e04ff3fa4d',
  social: '9e27d46b8abc8137e484638effd038cfc90c9000d905b44c1e7c8af5c0d65375',
  logo: 'e8d8718d1d1176beb4ac176991377874b0f1b7dfa7011e0a1173bb0fe8487258',
};

async function syncBrand(checkOnly) {
  let logo;
  for (const [name, expected] of Object.entries(fingerprints)) {
    const bytes = await readFile(path.join(root, 'public/assets/authzledger-' + name + '.png'));
    if (createHash('sha256').update(bytes).digest('hex') !== expected) {
      throw new Error('Unrecognised AuthzLedger artwork: ' + name);
    }
    if (name === 'logo') logo = bytes;
  }
  const teamLogo = path.join(root, 'team/static/logo.png');
  if (checkOnly) {
    if (!(await readFile(teamLogo)).equals(logo)) throw new Error('Team logo differs from the approved product logo');
  } else {
    await writeFile(teamLogo, logo);
  }
}

if (require.main === module) {
  syncBrand(process.argv.includes('--check')).catch(error => { console.error(error.message); process.exitCode = 1; });
}
module.exports = {syncBrand};

// © Nasser Aldin Farag (0xFarag). All rights reserved.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createHash} = require('node:crypto');
const root = path.resolve(__dirname,'..');
const read = file => fs.readFileSync(path.join(root,file));
test('brand outputs use the pinned 1.5.0 N-shield and contain the public copyright and intended dimensions', () => {
  const original=read('public/assets/0xfarag-original.png');
  assert.equal(createHash('sha256').update(original).digest('hex'),'815c7713f48eb136d6a4701bc2f2126d50f9b8b591b61cdb8f94bc81a37bdee4');
  for (const [name,width,height] of [['icon',48,48],['touch',180,180],['social',1200,630],['logo',256,256]]) {
    const png=read('public/assets/authzledger-'+name+'.png');
    assert.equal(png.toString('ascii',12,16),'IHDR');
    assert.equal(png.readUInt32BE(16),width);
    assert.equal(png.readUInt32BE(20),height);
    assert(png.includes(Buffer.from('Copyright\0© Nasser Aldin Farag (0xFarag). All rights reserved.','latin1')));
  }
  assert.deepEqual(read('team/static/logo.png'),read('public/assets/authzledger-logo.png'));
  const text=read('scripts/proof-brand-card.html').toString('utf8');
  for (const caption of ['SHOW THE','PROOF.','0xFarag','AuthzLedger · From scope to proof','#071722','#C8A66B','#43D6CF']) assert(text.includes(caption));
});

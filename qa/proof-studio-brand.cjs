// © Nasser Aldin Farag (0xFarag). All rights reserved.
const test = require('node:test');
const {syncBrand} = require('../scripts/render-proof-brand.cjs');

test('the website and Team Studio ship the approved gold A from commit 4072c94', async () => {
  await syncBrand(true);
});

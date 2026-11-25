// © Nasser Aldin Farag (0xFarag). All rights reserved.
// Run with node scripts/render-proof-brand.cjs after installing the QA Playwright dependency.
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require(require.resolve('playwright',{paths:[path.join(__dirname,'../qa')]}));
const root = path.resolve(__dirname,'..');
const assets = path.join(root,'public/assets');
const rights = '© Nasser Aldin Farag (0xFarag). All rights reserved.';

async function dataUrl(file,type) {
  return 'data:'+type+';base64,'+(await fs.readFile(file)).toString('base64');
}

// Store copyright even in the small icons, where a caption would be unreadable.
function includeRights(png) {
  const type=Buffer.from('tEXt','ascii');
  const data=Buffer.from('Copyright\0'+rights,'latin1');
  let crc=0xffffffff;
  for (const byte of Buffer.concat([type,data])) {
    crc ^= byte;
    for (let bit=0;bit<8;bit++) crc = crc&1 ? (crc>>>1)^0xedb88320 : crc>>>1;
  }
  const size=Buffer.alloc(4),checksum=Buffer.alloc(4);
  size.writeUInt32BE(data.length);
  checksum.writeUInt32BE((crc^0xffffffff)>>>0);
  // Add an ancillary chunk immediately before IEND; pixel data is untouched.
  return Buffer.concat([png.subarray(0,-12),size,type,data,checksum,png.subarray(-12)]);
}

async function render() {
  const [original,outfit,fraunces,layout]=await Promise.all([
    dataUrl(path.join(assets,'0xfarag-original.png'),'image/png'),
    dataUrl(path.join(root,'team/static/fonts/Outfit.ttf'),'font/ttf'),
    dataUrl(path.join(root,'team/static/fonts/Fraunces.ttf'),'font/ttf'),
    fs.readFile(path.join(__dirname,'proof-brand-card.html'),'utf8')
  ]);
  const browser=await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  try {
    for (const [kind,width,height,file] of [
      ['share',1200,630,'authzledger-social.png'],['icon',48,48,'authzledger-icon.png'],['icon',180,180,'authzledger-touch.png'],
      ['icon',256,256,'authzledger-logo.png']
    ]) {
      const page=await browser.newPage({viewport:{width,height},deviceScaleFactor:1});
      try {
        const html=layout.replaceAll('@@MODE@@',kind).replaceAll('@@MARK@@',original)
          .replaceAll('@@OUTFIT@@',outfit).replaceAll('@@FRAUNCES@@',fraunces);
        await page.setContent(html);
        await page.evaluate(async()=>{await document.fonts.ready; await document.getElementById('source').decode();});
        await fs.writeFile(path.join(assets,file),includeRights(await page.screenshot()));
      } finally {await page.close();}
    }
    await fs.copyFile(path.join(assets,'authzledger-logo.png'),path.join(root,'team/static/logo.png'));
  } finally {await browser.close();}
}
render().catch(error=>{console.error(error);process.exitCode=1;});

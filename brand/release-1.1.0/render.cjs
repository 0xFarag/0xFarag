const fs=require('fs'),path=require('path'),crypto=require('crypto');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const out=path.resolve(process.argv[2]||__dirname);
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROME_EXECUTABLE?{executablePath:process.env.CHROME_EXECUTABLE}:{})});
 for(const [name,width,height] of [['launch-landscape',1600,1000],['launch-portrait',1080,1350]]){
  const page=await browser.newPage({viewport:{width,height},deviceScaleFactor:1});
  await page.setContent('<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;width:100%;height:100%;overflow:hidden}svg{display:block}</style></head><body>'+fs.readFileSync(path.join(out,name+'.svg'),'utf8')+'</body></html>');
  await page.evaluate(()=>document.fonts.ready);
  await page.screenshot({path:path.join(out,name+'.png')});
  await page.close();
 }
 const metadataPath=path.join(out,'provenance.json'),metadata=JSON.parse(fs.readFileSync(metadataPath));
 metadata.rendering={browser:await browser.version(),scale:1,method:'SVG rendered by pinned Chromium; all screenshot content is embedded without retouching'};
 metadata.files={};
 for(const file of ['studio-source.png','launch-landscape.svg','launch-landscape.png','launch-portrait.svg','launch-portrait.png'])metadata.files[file]=crypto.createHash('sha256').update(fs.readFileSync(path.join(out,file))).digest('hex');
 fs.writeFileSync(metadataPath,JSON.stringify(metadata,null,2)+'\n');
 await browser.close();
 console.log(JSON.stringify({output:out,files:Object.keys(metadata.files),browser:metadata.rendering.browser}));
})().catch(error=>{console.error(error);process.exitCode=1;});

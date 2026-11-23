// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
// Independent local parser checks. SAX emulates XML traversal for Node; browser tests use DOMParser.
const assert=require('node:assert/strict'), fs=require('node:fs'), path=require('node:path');
const {test}=require('node:test'),vm=require('node:vm'),crypto=require('node:crypto'),sax=require('sax');
const root=process.env.AUTHZ_IMPORT_ROOT || path.join(__dirname,'../public/import');
const fixtures=path.join(__dirname,'fixtures');
class XmlNode {
  constructor(name,attrs){this.tagName=name;this.attrs=attrs;this.children=[];this.parts=[];}
  get textContent(){return this.parts.map(it=>typeof it==='string'?it:it.textContent).join('');}
  getAttribute(key){return this.attrs[key]??null;}
}
class DOMParser {
  parseFromString(input) {
    const parser=sax.parser(true),stack=[]; let documentElement,invalid=false;
    parser.onopentag=({name,attributes})=>{const node=new XmlNode(name,attributes), parent=stack.at(-1); if(parent){parent.children.push(node);parent.parts.push(node);}else{documentElement=node;}stack.push(node);};
    parser.ontext=parser.oncdata=text=>{if(stack.at(-1))stack.at(-1).parts.push(text);};
    parser.onclosetag=()=>{stack.pop();}; parser.onerror=()=>{invalid=true;};
    try{parser.write(input).close();}catch{invalid=true;}
    return {documentElement,doctype:null,querySelector:()=>invalid?{}:null};
  }
}
class XMLSerializer{serializeToString(node){return JSON.stringify([node.tagName,node.attrs,node.textContent,node.children.map(x=>this.serializeToString(x))]);}}
const context=vm.createContext({TextEncoder,TextDecoder,URL,crypto:crypto.webcrypto,DOMParser,XMLSerializer});
vm.runInContext(fs.readFileSync(path.join(root,'adapters.js'),'utf8')+'\nthis.api=AuthzImport;',context);
const api=context.api,enc=text=>new TextEncoder().encode(text);
const cases={nikto:['nikto.xml',2],ffuf:['ffuf.json',3],gobuster:['gobuster.txt',3],burp:['burp.xml',1],nmap:['nmap.xml',1],nessus:['nessus.nessus',1],cobalt:['cobalt.json',1]};
for(const [source,[file,count]] of Object.entries(cases))test(source+' fixture and example',async()=>{
  const bytes=fs.readFileSync(path.join(fixtures,file)), report=await api.parse(source,bytes);
  assert.equal(report.rows.length,count);assert.equal(report.digest,crypto.createHash('sha256').update(bytes).digest('hex'));
  assert.ok(report.rows.every(r=>/^[0-9a-f]{64}$/.test(r.fingerprint)));
  assert.doesNotMatch(JSON.stringify(report),/private-path|PRIVATE_PAYLOAD|app\.example/);
  assert.ok((await api.parse(source,enc(api.samples[source]))).rows.length>0);
  if(source==='ffuf')assert.equal(report.rows[0].fingerprint,report.rows[2].fingerprint);
  if(source==='gobuster'){assert.equal(report.rows[0].asset,'');assert.equal(report.rows[0].identity,null);assert.equal(report.rows[2].locator,'Zeile 4');}
});
for(const [i,c] of JSON.parse(fs.readFileSync(path.join(fixtures,'invalid-cases.json'))).entries())test('invalid input '+(i+1)+' ('+c.source+')',async()=>{
  const raw=c.repeat?c.repeat.repeat(c.count):c.ffufRows?JSON.stringify({results:Array(c.ffufRows).fill({url:'https://app.example/',status:200})}):c.text.replaceAll('\\n','\n');
  await assert.rejects(api.parse(c.source,enc(raw)),err=>err instanceof api.ImportError);
});
test('invalid UTF-8 rejected',async()=>{await assert.rejects(api.parse('ffuf',new Uint8Array([255])),err=>err instanceof api.ImportError);});

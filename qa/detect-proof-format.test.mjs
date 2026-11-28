// © Nasser Aldin Farag (0xFarag). All rights reserved.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {detectProofFile} from '../team/static/detect-proof-format.mjs';

const detect = raw => detectProofFile(new Blob([raw]));
const line = JSON.stringify;

test('detects existing exporter samples by their contents', async () => {
  for (const [name,format] of [
    ['nikto.xml','nikto'], ['nessus.nessus','nessus'], ['burp.xml','burp'], ['nmap.xml','nmap'], ['cobalt.json','cobalt']
  ]) {
    const data = await readFile(new URL('./fixtures/'+name,import.meta.url));
    assert.equal(await detect(data),format,name);
  }
});

test('detects each supported native evidence profile without a filename', async () => {
  const node = {type:'node',id:'1',labels:['Group'],properties:{domain:'example.test'}};
  const relation = {type:'relationship',id:'2',label:'MemberOf',start:{id:'1'},end:{id:'3'}};
  const match = {type:'http','template-id':'sample','matched-at':'https://app.example','matcher-status':true};
  for (const [content,expected] of [
    [line(node)+'\n'+line(relation),'neo4j'],
    [line({meta:{type:'groups',version:5},data:[]}),'bloodhound'],
    [line({site:[{alerts:[]}]}),'zap'],
    [line(match)+'\n'+line(match),'nuclei'],
    ['\ufeffTarget URL,Place,Parameter,Technique(s),Note(s)\r\n','sqlmap'],
    [line({log:{version:'1.2',entries:[]}}),'har'],
    [line({openapi:'3.0.0',paths:{},info:{}}),'openapi']
  ]) assert.equal(await detect(content),expected,expected);
  assert.equal(await detect(line(match)+'\n'+line(node)),null);
  assert.equal(await detect(line({...match,log:{version:'1.2',entries:[]}})),null);
});

test('malformed, unsupported or oversized inputs retain manual selection', async () => {
  assert.equal(await detect('<test><!-- <niktoscan> --></test>'),null);
  assert.equal(await detect('<!DOCTYPE items SYSTEM "example"><items/>'),null);
  assert.equal(await detect('<!DOCTYPE items [<!ENTITY e "x">]><items/>'),null);
  assert.equal(await detect('<items><item><price>20</price></item></items>'),null);
  assert.equal(await detect(line({observations:[]})),null);
  assert.equal(await detect(new Uint8Array([0xFF])),null);
  assert.equal(await detectProofFile(null),null);
  assert.equal(await detectProofFile({size:1024*1024+1,arrayBuffer(){assert.fail('excess file read');}}),null);
});

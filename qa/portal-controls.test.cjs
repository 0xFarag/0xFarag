// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const context = vm.createContext({URL});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../public/import/har-controls.js'),'utf8'), context);
const assess = vm.runInContext('AuthzHarControls.assess', context);
const field = (name,value) => ({name,value});
// Synthetic captures with ordinary HTML responses. The expected states below
// are set independently of the implementation. All tests run without network APIs.
function capture(headers) {
  return {request:{url:'https://fixture.example/private?token=do-not-export',method:'GET'},
    response:{status:200,redirectURL:'',content:{mimeType:'text/html; charset=UTF-8',text:'private response'},headers}};
}
const inspect = entry => JSON.parse(JSON.stringify(assess(entry)));
const outcome = (id,status,reason) => ({id,status,reason});
test('both controls read only explicit values in eligible captured responses', () => {
  const sample = capture([field(':status','200'), field('cOnTeNt-TyPe','text/HTML; charset=UTF-8'),
    field('X-CONTENT-TYPE-OPTIONS','\tNoSNiFf  '), field('Strict-Transport-Security','max-age=31536000; includeSubDomains'),
    field('Set-Cookie','do-not-export')]);
  assert.deepEqual(inspect(sample), [outcome('nosniff','met','valid'),outcome('hsts','met','valid')]);
  assert.doesNotMatch(JSON.stringify(inspect(sample)), /token|private|cookie|do-not-export|fixture\.example|31536000/i);
});
test('missing, corrupt and empty lists are unknown; a missing header in a nonempty list is described as absent in that capture', () => {
  const unknown = [outcome('nosniff','unknown','headers-unavailable'),outcome('hsts','unknown','headers-unavailable')];
  for (const value of [undefined,null,{},[],[{name:'bad name',value:'value'}],[{name:'Via',value:null}],Array(1025).fill(field('a','x'))]) {
    assert.deepEqual(inspect(capture(value)), unknown);
  }
  assert.deepEqual(inspect(capture([field('Content-Type','text/html')])),
    [outcome('nosniff','deviation','absent-in-capture'),outcome('hsts','deviation','absent-in-capture')]);
});
test('HSTS grammar handles quoted extensions, duplicate directives, zero and nonnumeric lifetimes', () => {
  const state = value => inspect(capture([field('Strict-Transport-Security',value)]))[1];
  for (const value of ['MAX-AGE="001"','; ext="one;two,three"; max-age=001; ; IncludeSubDomains;',
    'max-age = "2\\3"; ext="quoted\\"text";preload','max-age=123456789012345678901234567890']) {
    assert.deepEqual(state(value),outcome('hsts','met','valid'),value);
  }
  for (const value of ['max-age=0','includeSubDomains; max-age="0000"'])
    assert.deepEqual(state(value),outcome('hsts','deviation','disabled'),value);
  for (const value of ['', 'max-age','max-age=','max-age=-2','max-age=3s','max-age=2 max-age=4',
    'max-age="3','max-age=1; M a', 'max-age=2; includeSubDomains=1','max-age=3; Max-Age=2','max-age=1; ext; EXT']) {
    assert.deepEqual(state(value),outcome('hsts','deviation','invalid-value'),value);
  }
});
test('duplicate fields and redacted or joined values preserve uncertainty separately for each control', () => {
  assert.deepEqual(inspect(capture([field('X-Content-Type-Options','nosniff'),field('x-content-type-options','other'),
    field('strict-transport-security','max-age=5, max-age=3')])),
    [outcome('nosniff','unknown','ambiguous'),outcome('hsts','unknown','ambiguous')]);
  assert.deepEqual(inspect(capture([field('X-Content-Type-Options','off'), field('strict-transport-security','[redacted]')])),
    [outcome('nosniff','deviation','invalid-value'),outcome('hsts','unknown','ambiguous')]);
  assert.deepEqual(inspect(capture([field('X-Content-Type-Options','nosniff, custom'), field('Strict-Transport-Security','max-age=0'),
    field('Strict-Transport-Security','max-age=999')])),
    [outcome('nosniff','unknown','ambiguous'),outcome('hsts','unknown','ambiguous')]);
});
test('the profile excludes unrelated methods, redirects, non-HTML, HTTP and responses without a complete representation', () => {
  for (const [req,resp] of [[{method:'POST'},{}],[{url:'http://fixture.example/path'},{}],
    [{url:'https://['},{}], [{},{status:0}],[{},{status:301}],[{},{status:404}],[{},{status:205}],[{},{status:206}],
    [{},{status:204}],[{},{redirectURL:'https://other.example/'}],[{},{content:{mimeType:'application/json'}}],
    [{},{content:{}}], [{},{headers:[field('Content-Type','application/json')]}]]) {
    const entry = capture([field('Via','x')]); Object.assign(entry.request,req); Object.assign(entry.response,resp);
    assert.equal(assess(entry),null);
  }
  for (const ip of ['192.0.2.2','[2001:db8::2]']) {
    const entry = capture([field('X-Content-Type-Options','nosniff'),field('Strict-Transport-Security','max-age=10')]);
    entry.request.url = 'https://'+ip+'/';
    assert.deepEqual(inspect(entry),[outcome('nosniff','met','valid'),outcome('hsts','unknown','ip-host')]);
  }
});

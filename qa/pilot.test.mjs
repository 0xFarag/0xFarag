// © Nasser Aldin Farag (0xFarag). All rights reserved.
import test from 'node:test';
import assert from 'node:assert/strict';
import {letter} from '../public/pilot.mjs';
import workspace from '../api/workspace.js';
test('Offer reflects explicit Guided selection and includes the acceptance and credit terms',()=>{
  const buyer={organisation:'Scope AG',contact:'A. Muster',email:'team@example.org',guided:false};
  for(const lang of ['de','en','fr','it','ar']) {
    const basic=letter(buyer,lang,'2026-11-25');
    assert.ok(basic.split('\n').includes('contact@authzledger.com'));
    assert.match(basic,/not_retested/);assert.match(basic,/Team.*Consultancy/);assert.match(basic,/© Nasser Aldin Farag/);assert.doesNotMatch(basic,/4’800/);
    const guided=letter({...buyer,guided:true},lang,'2026-11-25');assert.match(guided,/4’800/);assert.match(guided,/90/);
  }
});
test('Workspace entry uses only the administrator-configured HTTPS origin',()=>{
  const old=process.env.AUTHZLEDGER_TEAM_ORIGIN;
  try {
    for(const [origin,ok] of [['',false],['http://localhost',false],['https://user:pass@example.org',false],['https://example.org/?redirect=evil',false],['https://team.example.org',true]]) {
      process.env.AUTHZLEDGER_TEAM_ORIGIN=origin;
      workspace({method:'GET',query:{origin:'https://wrong.example'}},{setHeader(){},status(n){assert.equal(n,200);return this;},json(v){assert.equal(v.available,ok);if(ok)assert.equal(v.origin,origin);}});
    }
  } finally { if(old===undefined)delete process.env.AUTHZLEDGER_TEAM_ORIGIN;else process.env.AUTHZLEDGER_TEAM_ORIGIN=old; }
});

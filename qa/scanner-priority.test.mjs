// © Nasser Aldin Farag (0xFarag). All rights reserved.
import assert from 'node:assert/strict';
import test from 'node:test';
import {scannerPriorities} from '../team/static/scanner-priority.mjs';

test('priorities preserve assessment and budget status and sort scoped scanner hints independently of import order',()=>{
  function finding(id,source,severity,host='app.example',status='inconclusive') {
    return {id,status,observation:{id,source,severity,host,rule:'audit'}};
  }
  const findings=[
    finding('z','Nuclei','high'), finding('a','Nuclei','high'), finding('b','Nessus','high'),
    finding('c','Nessus','critical','app.example','budget_blocked'), finding('d','Nessus','critical','other.example'),
    finding('e','Burp','critical'), finding('f','Nessus','medium'), finding('g','Nuclei',undefined),
    finding('h','Nuclei','high','app.example','out_of_scope')
  ];
  const report={scope:{hosts:['app.example']},findings};
  const expected=['c','b','a','z'];
  assert.deepEqual(scannerPriorities(report).map(row=>row.id),expected);
  assert.deepEqual(scannerPriorities({...report,findings:[...findings].reverse()}).map(row=>row.id),expected);
  assert.equal(scannerPriorities(report)[0].status,'budget_blocked');
  assert.equal(findings[0].id,'z');
  assert.deepEqual(scannerPriorities(null),[]);
});

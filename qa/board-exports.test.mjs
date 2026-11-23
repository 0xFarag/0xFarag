import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {makeCustomerReport, makeTicket} from '../public/workbench/exports.mjs';
import {parseProjection, statusLabels} from '../public/workbench/model.mjs';

const fixture = async name => parseProjection(await readFile(new URL('../public/proof/' + name, import.meta.url)));
const retest = await fixture('mixed-c-result.json');
const finding = await fixture('mixed-b-result.json');
const blue = await fixture('blue-evidence-example.json');
const languages = {de:'Kundenbericht', en:'Client report', fr:'Rapport client', it:'Rapporto per il cliente', ar:'تقرير العميل'};

test('localized standalone HTML and Markdown report every case regardless of review state', () => {
  const reviews = new Map([[retest.rows[1].id, {state:'reviewed', note:'SECRET-PRIVATE-NOTE'}]]);
  for (const [language, title] of Object.entries(languages)) {
    for (const format of ['html', 'markdown']) {
      const {text, mime, filename} = makeCustomerReport(retest, {language, format, reviews});
      assert.ok(text.includes(title) && text.includes(retest.digest) && text.includes(retest.scope));
      for (const row of retest.rows) assert.ok(text.includes(row.binding));
      assert.ok(text.includes(retest.rows[0].details.find(d => d.label === 'Aktueller Befund').value));
      assert.ok(!text.includes('SECRET-PRIVATE-NOTE') && !text.includes(retest.rows[0].id));
      if (format === 'html') {
        assert.match(mime, /text\/html/);
        assert.ok(filename.endsWith('-' + language + '.html'));
        assert.equal((text.match(/<article>/gu) || []).length, 2);
        assert.ok(text.includes('lang="' + language + '"') && text.includes(language === 'ar' ? 'dir="rtl"' : 'dir="ltr"'));
        assert.match(text, /Content-Security-Policy/u);
        assert.ok(!/<script|https?:\/\/|<a href|<form/iu.test(text));
      } else {
        assert.match(mime, /text\/markdown/);
        assert.ok(filename.endsWith('-' + language + '.md'));
        assert.equal((text.match(/^### /gmu) || []).length, 2);
      }
    }
  }
  const {text} = makeCustomerReport(retest, {language:'en', format:'markdown', reviews});
  for (const count of ['Cases in scope** · 2','Fix verified by retest** · 1','Not retested** · 1','Open** · 1','Reviewed** · 1']) assert.ok(text.includes(count));
  assert.doesNotMatch(text.split('### Case 2')[1], /Retest evidence/);
});

test('one developer ticket carries source, finding and control context in both formats', () => {
  const fields = {language:'en', owner:'AppSec', due:'2028-02-29', subject:'Header review', remediation:'Set the required header', acceptance:'Recheck the same response', reviewState:'follow_up'};
  for (const format of ['github','jira']) {
    const artifact = makeTicket(finding, 0, {...fields, format});
    assert.ok(artifact.text.startsWith(format === 'github' ? '# Header review\n' : 'Header review\n'));
    for (const value of [fields.owner, fields.due, fields.remediation, fields.acceptance, finding.digest,
      finding.rows[0].binding, 'Required HTTP response header is missing', 'Follow-up needed']) assert.ok(artifact.text.includes(value));
    assert.ok(!artifact.text.includes(finding.rows[1].binding));
    assert.ok(artifact.filename.endsWith(format === 'github' ? '-en.md' : '-en.txt'));
  }
  const hint = makeTicket(finding, 1, {language:'en',format:'jira'}).text;
  assert.match(hint,/Unverified scanner hint/u);
  assert.doesNotMatch(hint,/Correct the finding/u);
});

test('private fields, raw observations, and executable strings never flow into the customer handover', () => {
  const malicious = {id:'<svg/onload=alert(1)>', source:'token://secret', status:'hint', binding:'b'.repeat(64),
    title:'PRIVATE_TITLE', summary:'PRIVATE_SUMMARY', details:[{label:'PRIVATE_DETAIL', value:'<img src=x>'}],
    reference:{source:'private_source',file_sha256:'not-a-digest',locator:'javascript:alert(1)',fingerprint:'bad-fingerprint'}};
  const model = {kind:'manual', digest:'a'.repeat(64), assessment:'raw assessment',scope:'raw scope', rows:[malicious]};
  for (const format of ['html','markdown']) {
    const {text} = makeCustomerReport(model,{language:'en',format,reviews:new Map([[malicious.id,{state:'todo',note:'private note'}]])});
    assert.doesNotMatch(text, /PRIVATE_|private note|<svg|<img|javascript:|token:|raw scope|raw assessment|bad-fingerprint|private_source/u);
    assert.ok(text.includes(malicious.binding));
  }
  const attack = '<b> & @someone [follow](https://example.invalid)';
  const remediation = 'first\n' + String.fromCharCode(96).repeat(6) + '\n# disguised heading';
  const result = makeTicket(model,0,{subject:attack, remediation}).text;
  assert.doesNotMatch(result.split('\n')[0], /<b>|@someone|\[follow\]/u);
  assert.ok(result.includes(String.fromCharCode(96).repeat(7) + '\n' + remediation));
});

test('every workbench evidence status is available in each locale, including an empty scope', () => {
  for (const language of Object.keys(languages)) {
    const rows = Object.keys(statusLabels).map(status => ({id:status, binding:'f'.repeat(64), status}));
    const model = {kind:'inventory', digest:'e'.repeat(64), rows};
    for (let index=0; index<rows.length; index++) assert.doesNotMatch(makeTicket(model,index,{language}).text,/undefined/u);
    assert.doesNotMatch(makeCustomerReport(model,{language}).text,/undefined/u);
    assert.equal((makeCustomerReport({...model,rows:[]},{language}).text.match(/<article>/gu) || []).length,0);
  }
});

test('SOC counts and imported reference positions are safe and traceable', () => {
  assert.match(makeCustomerReport(blue,{language:'en',format:'markdown'}).text, /Events linked to alerts \/ eligible events/u);
  const row={id:'internal-id', binding:'b'.repeat(64), status:'import_unassessed', reference:{file_sha256:'b'.repeat(64), locator:'Zeile 23',fingerprint:'c'.repeat(64)}};
  const model={kind:'evidence_index',digest:'a'.repeat(64),rows:[row]};
  const {text}=makeCustomerReport(model,{language:'en',format:'markdown'});
  assert.ok(text.includes('Line** · 23') && text.includes(row.reference.fingerprint));
  assert.ok(!text.includes('internal-id'));
});

test('invalid scope, language, date, case index and format are rejected', () => {
  for (const index of [-1,2,0.5]) assert.throws(() => makeTicket(retest,index));
  for (const due of ['2027-02-29','2027-13-01','2027-1-1']) assert.throws(() => makeTicket(retest,0,{due}));
  assert.throws(() => makeTicket(retest,0,{language:'constructor'}));
  assert.throws(() => makeTicket(retest,0,{format:'url'}));
  assert.throws(() => makeTicket(retest,0,{owner:'a'.repeat(161)}));
  assert.throws(() => makeCustomerReport({...retest,digest:'<img>'}));
  assert.throws(() => makeCustomerReport(retest,{format:'pdf'}));
  assert.throws(() => makeCustomerReport(retest,{reviews:new Map([[retest.rows[0].id,{state:'confirmed'}]])}));
});

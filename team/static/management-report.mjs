// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {proofText} from './proof-texts.mjs';
import {sourceNames} from './proof-sources.mjs';

const baselineLabels = {
  confirmed:'baselineConfirmed', inconclusive:'baselineInconclusive', no_marker:'baselineNoMarker',
  budget_blocked:'baselineBudget', out_of_scope:'baselineOutside'
};
const retestLabels = {
  resolved_check:'retestResolved', regression:'retestRegression', inconclusive:'retestUnclear',
  testability_lost:'retestLost', testability_restored:'retestRestored',
  not_retested:'retestNotRepeated', not_applicable:'retestNotApplicable'
};
const severityLabels = {
  critical:'severityCritical', high:'severityHigh', medium:'severityMedium', low:'severityLow',
  info:'severityInfo', unknown:'severityUnknown'
};
export function managementHtml(report,locale) {
  const lang = ['de','en','fr'].includes(locale) ? locale : 'en';
  const t = key => proofText(key,lang);
  const doc = document.implementation.createHTMLDocument('AuthzLedger · '+t('managementTitle'));
  doc.documentElement.lang=lang;
  function element(tag,value) {
    const node=doc.createElement(tag);
    if (value !== undefined) node.textContent=String(value);
    return node;
  }
  const charset=element('meta'); charset.setAttribute('charset','utf-8'); doc.head.prepend(charset);
  const policy=element('meta'); policy.httpEquiv='Content-Security-Policy';
  policy.content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";
  const viewport=element('meta'); viewport.name='viewport'; viewport.content='width=device-width, initial-scale=1';
  const style=element('style',`
    * { box-sizing:border-box }
    body { margin:2rem auto; padding:0 1.3rem; max-width:48rem; color:#132d38; background:white; font:1rem/1.5 system-ui,sans-serif }
    header { border-bottom:3px solid #236862; padding-bottom:1.2rem }
    header p, h1, h2 { margin:.4rem 0 }
    h1, h2 { color:#092932; font-family:Georgia,serif }
    h1 { font-size:2.2rem } h2 { font-size:1.45rem }
    section { margin:1.75rem 0; break-inside:avoid }
    table { width:100%; border-collapse:collapse }
    td, th { border-bottom:1px solid #cddadc; padding:.35rem .2rem; text-align:start }
    th { font-weight:500 } td { text-align:end; font-variant-numeric:tabular-nums }
    code { overflow-wrap:anywhere } footer { margin-top:2rem; font-size:.85rem }
    @media print { body { margin:0; max-width:none } } @page { margin:17mm }
  `);
  doc.head.append(policy,viewport,style);
  const header=element('header');
  header.append(element('strong','AuthzLedger'),element('h1',t('managementTitle')),
    element('p',[t(report.mode),t('revision')+' '+report.revision,t('managementUnsigned')].join(' · ')),
    element('code',report.runId),element('p',new Intl.DateTimeFormat(lang,{
      dateStyle:'long',timeStyle:'short',timeZone:'UTC'
    }).format(new Date(report.updatedAt))+' UTC'));
  doc.body.append(header);
  function section(heading,rows) {
    const block=element('section'), table=element('table'), body=element('tbody');
    block.append(element('h2',heading));
    for (const [label,value] of rows) {
      const row=element('tr'), name=element('th',label); name.scope='row';
      row.append(name,element('td',value)); body.append(row);
    }
    table.append(body); block.append(table); doc.body.append(block);
  }
  const statusRows=(counts,labels)=>Object.entries(labels)
    .filter(([key])=>Object.hasOwn(counts,key)).map(([key,label])=>[t(label),counts[key]]);
  section(t('managementScope'),[
    [t('scopedHosts'),report.coverage.scopedHosts],[t('observedHosts'),report.coverage.observedScopedHosts],
    [t('budgetRemaining'),report.budget.remaining],[t('signedRevision'),report.handover.latestSignedRevision ?? t('noSignedRevision')]
  ]);
  if (report.evidenceStatus==='awaiting_evidence') {
    doc.body.append(element('p',t('awaitingEvidence')));
  } else {
    section(t('baselineVerdicts'),statusRows(report.baseline.byStatus,baselineLabels));
    const severities=report.scannerSignals?.bySeverity || {};
    if (Object.values(severities).some(n=>n>0)) section(t('scannerSeverities'),statusRows(severities,severityLabels));
    for (const [format,counts] of Object.entries(report.graphInventory?.byFormat || {})) {
      section(sourceNames[format]+' · '+t('mgmtGraphTitle'), [
        [t('mgmtDeclaredNodes'),counts.observedNodes],[t('mgmtReferencedNodes'),counts.referencedNodes],
        [t('mgmtRelationships'),counts.relationships]
      ]);
    }
    if (report.sqlmapResults) {
      section(t('mgmtSqlmapTitle'),statusRows(report.sqlmapResults,{
        reported:'mgmtSqlmapReported',disputed:'mgmtSqlmapDisputed',noTechniqueReported:'mgmtSqlmapNoTechnique'
      }));
    }
    section(t('latestRetest'),[[t('retestRuns'),report.retests.runs],...statusRows(report.retests.latestByStatus,retestLabels)]);
    section(t('sources'),Object.entries(report.sources.byFormat).map(([key,n])=>[sourceNames[key] || t(key),n]));
  }
  doc.body.append(element('footer','© Nasser Aldin Farag (0xFarag). All rights reserved.'));
  return '<!doctype html>\n'+doc.documentElement.outerHTML;
}

// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {inspectFile,reviewFile,checkVirusTotalReport,MAX_FILE_BYTES,MAX_REPORT_BYTES} from './file-inspection.mjs';

const hashPattern=/^[a-f0-9]{64}$/i;
const advice={name_signals:'repNameRisk',executable_format:'repExecutable',container_format:'repContainer',
  unrecognized_format:'repIdentify',recognized_format:'repCompare'};
const apiErrors={vt_not_found:'repNotFound',vt_rate_limited:'repLimit',vt_lookup_pending:'repBusy',
  vt_not_configured:'repOffline',forbidden:'repNoPermission',invalid_hash:'repHashError'};
const provenance={local_report:'repImported',virustotal:'repLive',cached_virustotal:'repCached'};

export function createFileReputation({request,t,download,onUnauthorized}) {
  const el=id=>document.getElementById('rep-'+id);
  const hashInput=el('hash');
  let path, access, local, result, localNote, reportNote, readingFile=false, working=false, revision=0, accessRevision=0;

  function hash() {
    const value=hashInput.value.trim();
    return hashPattern.test(value) ? value.toLowerCase() : '';
  }
  function resetSelection() {
    revision++;
    local=null; result=null; localNote=null; reportNote=null;
    readingFile=false; working=false;
  }
  function reset() {
    resetSelection();
    for (const id of ['hash','file','json']) el(id).value='';
    render();
  }
  function addText(parent,tag,value) {
    const node=document.createElement(tag); node.textContent=value; parent.append(node);
  }
  function render() {
    const digest=hash(), target=el('result'), localBox=el('local');
    localBox.replaceChildren(); target.replaceChildren();
    if (local) {
      const format=local.format.id==='unknown' ? t('repNoFormat') : local.format.id.toUpperCase();
      localBox.textContent=[t('repFileFacts'),local.size+' B',t('repFormat')+' · '+format,
        t(advice[reviewFile(local).reason])].join(' · ');
    } else if (localNote) localBox.textContent=t(localNote);
    else if (hashInput.value.trim()) localBox.textContent=t(digest ? 'repHashOnly' : 'repHashError');
    const availability = !access ? 'repChecking' : access.error ? 'repUnavailable' : !access.configured ?
      'repOffline' : !access.canLookup ? 'repNoPermission' : 'repConnected';
    el('access').textContent=t(availability);
    el('lookup').disabled=!digest || working || !access?.configured || !access.canLookup;
    el('json').disabled=!digest || working;
    el('export').disabled=!digest || working;
    el('clear').disabled=!hashInput.value && !localNote && !readingFile;
    if (result) {
      const {stats,analyzedAt}=result;
      const key=stats.malicious || stats.suspicious ? 'repDetected' :
        stats.harmless || stats.undetected ? 'repZero' : 'repInconclusive';
      addText(target,'h3',t(provenance[result.source]));
      addText(target,'p',t(key));
      addText(target,'p',[t('repMalicious')+' · '+stats.malicious,t('repSuspicious')+' · '+stats.suspicious].join(' / '));
      addText(target,'p',t('repAnalyzed')+' · '+(analyzedAt || t('repDateMissing')));
    } else if (reportNote || digest) addText(target,'p',t(reportNote || 'repUnknown'));
  }
  hashInput.addEventListener('input',()=>{resetSelection(); render();});
  el('clear').addEventListener('click',()=>{reset(); hashInput.focus();});
  el('file').addEventListener('change',async event=>{
    const file=event.target.files[0];
    event.target.value='';
    if (!file) return;
    resetSelection(); hashInput.value='';
    const version=revision;
    localNote='repReading'; readingFile=true; render();
    try {
      if (file.size>MAX_FILE_BYTES) throw Error('size');
      const data=await inspectFile(await file.arrayBuffer(),file.name);
      if (version!==revision) return;
      local=data; hashInput.value=data.sha256; localNote=null;
    } catch { if (version===revision) localNote='repBadFile'; }
    finally { if (version===revision) { readingFile=false; render(); } }
  });
  el('json').addEventListener('change',async event=>{
    const file=event.target.files[0], digest=hash();
    event.target.value='';
    if (!file || !digest || working) return;
    const version=revision;
    result=null; reportNote=null; working=true; render();
    try {
      if (file.size>MAX_REPORT_BYTES) throw Error('size');
      const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
      if (version!==revision) return;
      const checked=checkVirusTotalReport(local || {sha256:digest},JSON.parse(text));
      result={source:'local_report',stats:checked.stats,analyzedAt:checked.analyzedAt};
    } catch { if (version===revision) reportNote='repBadReport'; }
    finally { if (version===revision) { working=false; render(); } }
  });
  el('lookup').addEventListener('click',async()=>{
    const digest=hash();
    if (!path || !digest || working || !access?.configured || !access.canLookup) return;
    const version=revision;
    result=null; reportNote='repPending'; working=true; render();
    try {
      const data=await request(path+'/lookup','POST',{sha256:digest,consent:true});
      if (version!==revision) return;
      if (data.sha256!==digest || data.provider!=='VirusTotal') throw Error('mismatched report');
      result={source:data.cached ? 'cached_virustotal' : 'virustotal',stats:data.stats,analyzedAt:data.analysisDate};
      reportNote=null;
    } catch (error) {
      if (version!==revision) return;
      if (error.status===401) { onUnauthorized(error); return; }
      reportNote=apiErrors[error.message] || 'repUnavailable';
      if (error.message==='vt_not_configured') access={...access,configured:false};
      if (error.status===403) access={...access,canLookup:false};
    } finally { if (version===revision) { working=false; render(); } }
  });
  el('export').addEventListener('click',()=>{
    const digest=hash();
    if (!digest || working) return;
    download({
      schema:'authzledger.team-file-evidence.v1',signed:false,sha256:digest,
      input:local ? 'local_file' : 'supplied_hash',
      localInspection:local ? {sizeBytes:local.size,format:local.format.id,
        signals:local.signals.map(item=>item.id),review:reviewFile(local)} : null,
      reputation:result || {source:null,status: reportNote==='repNotFound' ? 'provider_not_found' :
        reportNote ? 'assessment_unavailable' : 'not_assessed'}
    },'AuthzLedger-File-'+digest+'.json');
  });
  async function open(base) {
    const version=++accessRevision;
    path=base+'/file-reputation';
    access=null; render();
    try {
      const state=await request(path+'/status');
      if (version===accessRevision) access=state;
    } catch(error) {
      if (version!==accessRevision) return;
      if (error.status===401) { onUnauthorized(error); return; }
      access={error:true};
    }
    if (version===accessRevision) render();
  }
  function clear() { ++accessRevision; path=null; access=null; reset(); }
  return {render,open,clear,resetInputs:reset};
}

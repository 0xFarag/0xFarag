// ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
import { parseProjection } from './model.mjs';

async function hash(text) {
  const data = new TextEncoder().encode('AuthzLedger / Synthetisches Vergleichsbeispiel / ' + text);
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  return Array.from(bytes, byte => byte.toString(16).padStart(2,'0')).join('');
}

export async function exampleSnapshots() {
  const firstFinding = await hash('Zugriff · Baseline');
  const secondFinding = await hash('Protokoll · Baseline');
  const common = {
    demo:'C', synthetic:true, assessment_id:'uebung-standvergleich',
    scope_digest:await hash('Scope'),
    baseline_execution_digest:await hash('Baseline'),
    sources:['synthetische-uebungsdaten']
  };
  async function snapshot(current) {
    const stage = current ? 'Stand 2' : 'Stand 1';
    const raw = {
      ...common, snapshot_digest:await hash(stage),
      current_execution_digest:await hash(stage + ' · Prüflauf'),
      transitions:[
        {case_id:'Zugriff', finding_id:'uebung-zugriff', status:current ? 'fix_verified' : 'violation_persists',
          baseline_finding_digest:firstFinding, current_finding_digest:await hash(stage + ' · Zugriff'),
          verification_level:'synthetic_fixture'},
        {case_id:'Protokoll', finding_id:'uebung-protokoll', status:'not_retested',
          baseline_finding_digest:secondFinding, current_finding_digest:null, verification_level:'synthetic_fixture'}
      ]
    };
    const model = await parseProjection(new TextEncoder().encode(JSON.stringify(raw)));
    return {model, key:model.digest, name:'Übungsfall · ' + stage};
  }
  return Promise.all([snapshot(false), snapshot(true)]);
}

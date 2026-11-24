// © Nasser Aldin Farag (0xFarag). All rights reserved.
import { languages, messages } from './texts.mjs';

const captions = {
  title: ['Minimaler Belegindex','Minimal evidence index','Index minimal des preuves','Indice minimo delle prove','الفهرس الأدنى للأدلة'],
  file: ['Quelldatei (SHA-256)','Source file (SHA-256)','Fichier source (SHA-256)','File sorgente (SHA-256)','الملف المصدر (SHA-256)'],
  record: ['Datensatz-Fingerabdruck','Record fingerprint','Empreinte de l’enregistrement','Impronta del record','بصمة السجل'],
  plan: ['Prüfplan-ID','Review plan ID','Identifiant du plan','ID del piano','معرّف خطة المراجعة'],
  revision: ['Revisions-ID','Revision ID','Identifiant de révision','ID revisione','معرّف المراجعة'],
  digest: ['Revisionsprüfsumme','Revision digest','Empreinte de la révision','Impronta della revisione','بصمة المراجعة'],
  parent: ['Vorgängerprüfsumme','Parent revision digest','Empreinte de la révision précédente','Impronta della revisione precedente','بصمة المراجعة السابقة'],
  empty: ['Kein verknüpfter Prüfplan.','No linked review plan.','Aucun plan associé.','Nessun piano collegato.','لا توجد خطة مراجعة مرتبطة.'],
  download: ['Unsignierten Belegindex speichern','Save unsigned evidence index','Enregistrer l’index non signé','Salva indice non firmato','حفظ الفهرس غير الموقّع'],
  compare: ['Original-JSON des Prüfplans lokal mit dieser Übergabe abgleichen','Compare the original review plan JSON with this handover locally','Comparer localement le JSON original du plan à cette remise','Confronta localmente il JSON originale del piano con questa consegna','مطابقة ملف JSON الأصلي لخطة المراجعة محلياً مع هذا التسليم'],
  match: ['Alle Revisionen stimmen mit der signierten Übergabe überein.','Every revision matches the signed handover.','Toutes les révisions correspondent à la remise signée.','Tutte le revisioni corrispondono alla consegna firmata.','تطابق جميع المراجعات التسليم الموقّع.'],
  mismatch: ['Der gewählte Prüfplan stimmt nicht mit dieser Übergabe überein.','The selected review plan does not match this handover.','Le plan sélectionné ne correspond pas à cette remise.','Il piano selezionato non corrisponde a questa consegna.','خطة المراجعة المحددة لا تطابق هذا التسليم.']
};

function element(tag, text) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}
function pair(list, label, value) {
  const entry = element('dd'), code = element('code', value);
  code.dir = 'ltr';
  entry.append(code);
  list.append(element('dt',label), entry);
}

export function indexPanel(index, language, save) {
  const locale = languages.indexOf(language);
  const t = key => captions[key][locale];
  const panel = element('details');
  panel.className = 'evidence-index';
  panel.append(element('summary', t('title')));
  const sources = element('dl');
  for (const ref of index.observations) {
    const role = messages[ref.role][locale], data = element('bdi',ref.format + ' #' + ref.record);
    const heading = element('dt', role + ' · ');
    heading.append(data); sources.append(heading);
    pair(sources,t('file'),ref.sha256);
    pair(sources,t('record'),ref.fingerprint);
  }
  panel.append(sources);
  if (!index.experiments.length) panel.append(element('p',t('empty')));
  for (const plan of index.experiments) {
    const chain = element('dl');
    pair(chain,t('plan'),plan.plan_id);
    for (const rev of plan.revisions) {
      pair(chain,t('revision'),rev.id);
      pair(chain,t('digest'),rev.sha256);
      if (rev.parent_sha256) pair(chain,t('parent'),rev.parent_sha256);
    }
    panel.append(chain);
    if (!save) {
      const label = element('label',t('compare')), field = element('input'), output = element('p');
      field.type = 'file'; field.accept = '.json,application/json';
      output.setAttribute('role','status');
      field.addEventListener('change',async () => {
        const file = field.files[0]; output.textContent = '';
        if (!file) return;
        let matches = false;
        try {
          if (file.size > 0 && file.size <= 8 * 1024 * 1024) {
            const raw = new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
            matches = await reviewMatches(raw,plan);
          }
        } catch { /* Show the localised mismatch and discard the file contents. */ }
        if (field.files[0] === file) output.textContent = t(matches ? 'match' : 'mismatch');
      });
      label.append(field); panel.append(label,output);
    }
  }
  if (save) {
    const button = element('button',t('download')); button.type = 'button'; button.className = 'secondary slim';
    button.addEventListener('click',save); panel.append(button);
  }
  return panel;
}

// Python's sorted UTF-8 projection contains only ASCII keys, strings and safe
// integral numeric fields. Nested object keys are sorted without changing arrays.
function canonicalRow(row) {
  return JSON.stringify(row,(_,value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
    return Object.fromEntries(Object.keys(value).sort().map(k => [k,value[k]]));
  });
}

export async function reviewMatches(text, plan) {
  const doc = JSON.parse(text);
  // An original Team export uses JSON.stringify(..., null, 2). Ignore formatting
  // whitespace, but reject duplicate keys and noncanonical string encodings.
  const compact = text.replace(/"(?:\\.|[^"\\])*"|[\t\r\n ]+/g, token => token[0] === '"' ? token : '');
  if (compact !== JSON.stringify(doc) || doc.schema !== 'authzledger.reproducibility-record/v1' ||
      doc.signed !== false || doc.plan_id !== plan.plan_id || !Array.isArray(doc.revisions) ||
      doc.revisions.length !== plan.revisions.length || !doc.revisions.length ||
      doc.latest_revision_sha256 !== plan.revisions.at(-1).sha256) return false;
  const utf8 = new TextEncoder();
  for (const [i,row] of doc.revisions.entries()) {
    const expected = plan.revisions[i], {sha256,...content} = row;
    if (row.id !== expected.id || sha256 !== expected.sha256 || row.parent_sha256 !== expected.parent_sha256 ||
        row.team_id !== doc.team_id || row.case_id !== doc.case_id || row.plan_id !== doc.plan_id) return false;
    const digest = await crypto.subtle.digest('SHA-256',utf8.encode(canonicalRow(content)));
    const hex = Array.from(new Uint8Array(digest), c => c.toString(16).padStart(2,'0')).join('');
    if (hex !== expected.sha256) return false;
  }
  return true;
}

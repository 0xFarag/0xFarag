// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {statusLabels} from './model.mjs';

const locales = ['de', 'en', 'fr', 'it', 'ar'];
const labels = {
  report: ['Kundenbericht', 'Client report', 'Rapport client', 'Rapporto per il cliente', 'تقرير العميل'],
  executive: ['Zusammenfassung', 'Executive summary', 'Synthèse', 'Sintesi', 'الملخص التنفيذي'],
  appendix: ['Technischer Beleganhang', 'Technical evidence appendix', 'Annexe technique des preuves', 'Allegato tecnico delle evidenze', 'ملحق الأدلة التقنية'],
  count: ['Fälle im Umfang', 'Cases in scope', 'Cas dans le périmètre', 'Casi inclusi', 'الحالات ضمن النطاق'],
  item: ['Fall', 'Case', 'Cas', 'Caso', 'الحالة'],
  decision: ['Quellergebnis', 'Source result', 'Résultat de la source', 'Esito della fonte', 'نتيجة المصدر'],
  review: ['Bearbeitungsstand', 'Review state', 'État de la revue', 'Stato della revisione', 'حالة المراجعة'],
  source: ['SHA-256 der Belegquelle', 'Evidence source SHA-256', 'SHA-256 de la source', 'SHA-256 della fonte', 'بصمة مصدر الأدلة SHA-256'],
  binding: ['Gebundene Belegreferenz', 'Bound evidence reference', 'Référence de preuve liée', 'Riferimento associato', 'مرجع الدليل المرتبط'],
  scope: ['Scope-Digest', 'Scope digest', 'Empreinte du périmètre', 'Impronta del perimetro', 'بصمة النطاق'],
  current: ['Retest-Befund', 'Retest evidence', 'Preuve du nouveau test', 'Evidenza del nuovo test', 'دليل إعادة الاختبار'],
  original: ['Ursprünglicher Befund', 'Original finding', 'Constat initial', 'Riscontro originale', 'النتيجة الأصلية'],
  findingHash: ['Befund-Digest', 'Finding digest', 'Empreinte du constat', 'Impronta del riscontro', 'بصمة النتيجة'],
  file: ['Quelldatei (SHA-256)', 'Source file (SHA-256)', 'Fichier source (SHA-256)', 'File sorgente (SHA-256)', 'الملف المصدر (SHA-256)'],
  record: ['Datensatz-Fingerabdruck', 'Record fingerprint', 'Empreinte de l’enregistrement', 'Impronta del record', 'بصمة السجل'],
  line: ['Zeile', 'Line', 'Ligne', 'Riga', 'السطر'],
  entry: ['Datensatz', 'Record', 'Enregistrement', 'Record', 'السجل'],
  signals: ['Ereignisse mit zugeordnetem Alarm / passende Ereignisse', 'Events linked to alerts / eligible events', 'Événements liés à une alerte / événements éligibles', 'Eventi associati ad allarmi / eventi idonei', 'الأحداث المرتبطة بتنبيه / الأحداث المطابقة'],
  boundaries: [
    'Die Zahlen gelten für die gewählte Belegquelle. Der Bearbeitungsstand dokumentiert die Sichtung. Ein Hinweis allein bestätigt keine Schwachstelle. Der Bericht ist unsigniert.',
    'Counts cover the selected evidence source. The review state records human review. A hint alone does not confirm a vulnerability. This report is unsigned.',
    'Les chiffres concernent la source sélectionnée. L’état de la revue indique le suivi humain. Un indice seul ne confirme aucune vulnérabilité. Ce rapport est non signé.',
    'I conteggi si riferiscono alla fonte selezionata. Lo stato di revisione indica la verifica umana. Un indizio da solo non conferma una vulnerabilità. Il rapporto non è firmato.',
    'تشمل الأعداد مصدر الأدلة المحدد. تعبّر حالة المراجعة عن المراجعة البشرية. لا تكفي الملاحظة وحدها لإثبات وجود ثغرة. هذا التقرير غير موقّع.'
  ],
  category: ['Quellprofil', 'Source profile', 'Profil de la source', 'Profilo della fonte', 'نوع المصدر'],
  finding: ['Konfigurationsprüfung', 'Configuration check', 'Contrôle de configuration', 'Verifica della configurazione', 'فحص الإعدادات'],
  retest: ['Selektiver Retest', 'Selective retest', 'Nouveau test sélectif', 'Ripetizione selettiva dei test', 'إعادة اختبار انتقائية'],
  inventory: ['Quelleninventar', 'Source inventory', 'Inventaire des sources', 'Inventario delle fonti', 'جرد المصادر'],
  evidence_index: ['Importierter Belegindex', 'Imported evidence index', 'Index de preuves importé', 'Indice delle evidenze importato', 'فهرس الأدلة المستورد'],
  blue: ['SOC-Signalbericht', 'SOC signal report', 'Rapport de signaux SOC', 'Rapporto dei segnali SOC', 'تقرير إشارات مركز العمليات الأمنية'],
  manual: ['Manuell erfasster Fall', 'Manually recorded case', 'Cas saisi manuellement', 'Caso registrato manualmente', 'حالة مسجّلة يدوياً'],
  owner: ['Verantwortlich', 'Owner', 'Responsable', 'Responsabile', 'المسؤول'],
  due: ['Fällig am', 'Due date', 'Échéance', 'Scadenza', 'تاريخ الاستحقاق'],
  remediation: ['Behebung / nächster Schritt', 'Remediation / next step', 'Correction / prochaine étape', 'Correzione / prossimo passo', 'المعالجة / الخطوة التالية'],
  acceptance: ['Abnahmekriterien', 'Acceptance criteria', 'Critères d’acceptation', 'Criteri di accettazione', 'معايير القبول'],
  unset: ['Noch festzulegen', 'To be defined', 'À définir', 'Da definire', 'يحدّد لاحقاً'],
  todo: ['Offen', 'Open', 'À examiner', 'Da esaminare', 'قيد الانتظار'],
  follow_up: ['Rückfrage nötig', 'Follow-up needed', 'Suivi nécessaire', 'Da approfondire', 'تحتاج إلى متابعة'],
  reviewed: ['Gesichtet', 'Reviewed', 'Examiné', 'Esaminato', 'تمت المراجعة'],
  requiredHeader: ['Vorgeschriebener HTTP-Antwortheader fehlt', 'Required HTTP response header is missing', 'En-tête de réponse HTTP obligatoire manquant', 'Intestazione di risposta HTTP obbligatoria mancante', 'ترويسة مطلوبة مفقودة من استجابة HTTP'],
  workItem: ['Arbeitsauftrag', 'Work item', 'Travail à réaliser', 'Intervento', 'المهمة'],
  activeFinding: ['Befund korrigieren und mit derselben Kontrolle nachprüfen.', 'Correct the finding and retest using the same control.', 'Corriger le constat et répéter le test avec le même contrôle.', 'Correggere il problema e ripetere il test con lo stesso controllo.', 'عالج المشكلة وأعد الاختبار باستخدام الضابط نفسه.'],
  reviewEvidence: ['Quellbeleg prüfen und den Entscheid dokumentieren.', 'Review the source evidence and document the decision.', 'Examiner la preuve source et documenter la décision.', 'Esaminare la fonte e documentare la decisione.', 'راجع دليل المصدر ووثّق القرار.'],
  scheduleRetest: ['Den ausgelassenen Fall für einen Retest einplanen.', 'Schedule a retest for the omitted case.', 'Planifier un nouveau test du cas omis.', 'Pianificare un nuovo test per il caso omesso.', 'حدّد موعداً لإعادة اختبار الحالة التي تم تجاوزها.'],
  verifyFix: ['Den Retest-Beleg mit der ursprünglichen Referenz abgleichen.', 'Compare the retest evidence with the original reference.', 'Comparer la preuve du nouveau test à la référence initiale.', 'Confrontare le evidenze del nuovo test con il riferimento originale.', 'قارن دليل إعادة الاختبار بالمرجع الأصلي.'],
  not_retested: ['Nicht erneut geprüft', 'Not retested', 'Non retesté', 'Non verificato di nuovo', 'لم يُعَد اختباره'],
  fix_verified: ['Fix im Retest bestätigt', 'Fix verified by retest', 'Correction vérifiée par un nouveau test', 'Correzione verificata da un nuovo test', 'تأكد الإصلاح بإعادة الاختبار'],
  inconclusive: ['Retest ohne eindeutiges Ergebnis', 'Inconclusive retest', 'Nouveau test non concluant', 'Nuovo test inconcludente', 'إعادة اختبار غير حاسمة'],
  violation_persists: ['Befund besteht weiter', 'Finding persists', 'Le constat persiste', 'Il problema persiste', 'المشكلة ما زالت قائمة'],
  testability_restored: ['Wieder prüfbar', 'Testability restored', 'Vérification à nouveau possible', 'Nuovamente verificabile', 'أصبح الاختبار ممكناً من جديد'],
  regression: ['Regression', 'Regression', 'Régression', 'Regressione', 'تراجع'],
  unchanged: ['Unverändert', 'Unchanged', 'Inchangé', 'Invariato', 'دون تغيير'],
  confirmed: ['Konfigurationsbefund bestätigt', 'Configuration finding confirmed', 'Constat de configuration confirmé', 'Problema di configurazione confermato', 'تأكدت مشكلة الإعدادات'],
  not_verified: ['Unbestätigter Scannerhinweis', 'Unverified scanner hint', 'Indice du scanner non vérifié', 'Segnalazione dello scanner non verificata', 'ملاحظة من الماسح لم يتم التحقق منها'],
  hint: ['Quellhinweis', 'Source hint', 'Indice de la source', 'Indizio dalla fonte', 'ملاحظة من المصدر'],
  observed: ['Beobachtung', 'Observation', 'Observation', 'Osservazione', 'رصد'],
  import_unassessed: ['Ungeprüfter Importbeleg', 'Unassessed imported evidence', 'Preuve importée non examinée', 'Evidenza importata non valutata', 'دليل مستورد لم يُقيَّم'],
  excluded: ['Ausgelassen', 'Excluded', 'Exclu', 'Escluso', 'مستبعد'],
  soc_observed: ['Alarm zugeordnet', 'Alert linked', 'Alerte corrélée', 'Allarme associato', 'تنبيه مرتبط'],
  soc_telemetry_only: ['Nur Telemetrie', 'Telemetry only', 'Télémétrie seule', 'Solo telemetria', 'بيانات رصد فقط'],
  soc_incomparable: ['Nicht zuordenbar', 'Cannot be correlated', 'Corrélation impossible', 'Non correlabile', 'تعذّر الربط'],
  soc_unavailable: ['Keine Signaldaten', 'No signal data', 'Aucune donnée de signal', 'Dati di segnale assenti', 'لا توجد بيانات إشارة']
};
const kinds = ['finding', 'retest', 'inventory', 'evidence_index', 'blue', 'manual'];
const states = ['todo', 'follow_up', 'reviewed'];
const isDigest = value => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);

function context(model, language) {
  const index = locales.indexOf(language);
  if (index < 0 || !kinds.includes(model?.kind) || !isDigest(model.digest) || !Array.isArray(model.rows)) {
    throw Error('Ungültige Belegquelle oder Ausgabesprache.');
  }
  return key => labels[key][index];
}

// Export positions and cryptographic references. Raw IDs, notes, paths, hostnames and
// free-form source details are intentionally never material for the outgoing document.
function evidenceFields(model, row, t) {
  if (!isDigest(row?.binding) || !Object.hasOwn(statusLabels, row.status)) throw Error('Ungültiger Beleg.');
  const fields = [[t(model.kind === 'retest' ? 'original' : 'binding'), row.binding]];
  const checkedDigest = (key, value) => { if (isDigest(value)) fields.push([t(key), value]); };
  if (model.kind === 'retest') checkedDigest('current', row.details?.find(detail => detail.label === 'Aktueller Befund')?.value);
  if (row.status === 'confirmed') checkedDigest('findingHash', row.details?.find(detail => detail.label === 'Befund-Digest')?.value);
  if (row.reference) {
    if (row.reference.file_sha256 !== row.binding) checkedDigest('file', row.reference.file_sha256);
    const position = /^(Zeile|Datensatz) ([1-9][0-9]{0,6})$/u.exec(row.reference.locator);
    if (position) fields.push([t(position[1] === 'Zeile' ? 'line' : 'entry'), position[2]]);
    checkedDigest('record', row.reference.fingerprint);
  }
  const signal = row.signalCoverage;
  if (signal && [signal.linked, signal.eligible].every(n => Number.isSafeInteger(n) && n >= 0)) {
    fields.push([t('signals'), signal.linked + ' / ' + signal.eligible]);
  }
  return fields;
}

function reviewState(state) {
  if (state == null) return 'todo';
  if (!states.includes(state)) throw Error('Unbekannter Bearbeitungsstand.');
  return state;
}

function html(text) {
  return String(text).replace(/[&<>"']/gu, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
}

function manualText(value, max) {
  if (value == null) return '';
  if (typeof value !== 'string' || value.length > max) throw Error('Ticketfeld ist ungültig oder zu lang.');
  return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu, '')
    .replace(/\r\n?/gu, '\n').trim();
}

function actionFor(status) {
  if (['confirmed', 'violation_persists', 'regression'].includes(status)) return 'activeFinding';
  if (status === 'not_retested') return 'scheduleRetest';
  if (status === 'fix_verified') return 'verifyFix';
  return 'reviewEvidence';
}

function markdownTitle(subject) {
  // Escape punctuation that could start Markdown, HTML, a mention, or a link.
  return subject.replace(/[^\p{L}\p{M}\p{N} ]/gu, c => '&#' + c.codePointAt(0) + ';');
}

function ticketBody(fields, format) {
  return fields.map(([label, value]) => {
    if (format === 'jira') return label + '\n' + value;
    // Fenced blocks keep user-authored action text, markup, links and mentions literal.
    const runs = value.match(/\x60+/gu) || [];
    const fence = String.fromCharCode(96).repeat(Math.max(3, ...runs.map(run => run.length + 1)));
    return '**' + label + '**\n\n' + fence + '\n' + value + '\n' + fence;
  }).join('\n\n');
}

const rights = '© Nasser Aldin Farag (0xFarag). All rights reserved.';

export function makeTicket(model, caseIndex, options = {}) {
  const {format = 'github', language = 'de'} = options;
  const t = context(model, language);
  if (!['github','jira'].includes(format) || !Number.isInteger(caseIndex) || caseIndex < 0 || caseIndex >= model.rows.length) {
    throw Error('Wählen Sie einen Fall und ein Ticketformat.');
  }
  const row = model.rows[caseIndex];
  const refs = evidenceFields(model, row, t);
  const github = format === 'github';
  const subject = manualText(options.subject, 160).replace(/\n/gu, ' ');
  const description = row.status === 'confirmed' && model.kind === 'finding' ? t('requiredHeader') : t(row.status);
  const title = subject ? (github ? markdownTitle(subject) : subject) : 'AuthzLedger · ' + t('item') + ' ' + (caseIndex + 1) + ' · ' + description;
  const fields = [[t('item'), String(caseIndex + 1)], [t('category'), t(model.kind)], [t('decision'), description],
    [t('review'), t(reviewState(options.reviewState))], [t('workItem'), t(actionFor(row.status))]];
  for (const [key, max] of [['owner',160], ['due',10], ['remediation',4000], ['acceptance',4000]]) {
    const value = manualText(options[key], max);
    if (key === 'due' && value) {
      const day = /^\d{4}-\d\d-\d\d$/u.test(value) && new Date(value + 'T00:00:00Z');
      if (!day || !Number.isFinite(+day) || day.toISOString().slice(0,10) !== value) throw Error('Ungültiges Fälligkeitsdatum.');
    }
    fields.push([t(key), value || t('unset')]);
  }
  fields.push([t('source'), model.digest], ...refs);
  return {
    text: (github ? '# ' : '') + title + '\n\n' + ticketBody(fields, format) + '\n\n' + rights + '\n',
    mime: (github ? 'text/markdown' : 'text/plain') + ';charset=utf-8',
    filename: 'authzledger-' + format + '-' + model.digest.slice(0,12) + '-' + (caseIndex + 1) + '-' + language + (github ? '.md' : '.txt')
  };
}

const reportCss = `
  :root{font-family:system-ui,sans-serif;color:#16283d;background:#fff;line-height:1.55}
  body{max-width:54rem;margin:0 auto;padding:2rem clamp(1rem,5vw,3rem)}
  header{border-bottom:3px solid #a07b40} header p{color:#46586e}
  h1,h2,h3{line-height:1.2;color:#153765} h2{margin-top:2rem} article{border-top:1px solid #c8cfda}
  dl{display:grid;grid-template-columns:minmax(9rem,1fr) minmax(0,2fr);gap:.3rem 1rem}
  dt{font-weight:600} dd{margin:0;overflow-wrap:anywhere} ul{padding-inline-start:1.4rem}
  @media(max-width:38rem){dl{display:block} dd{margin-bottom:.7rem}}
  @media print{body{max-width:none;padding:0;font-size:10pt} h2,h3{break-after:avoid} article{break-inside:avoid} @page{margin:16mm}}
`;

export function makeCustomerReport(model, options = {}) {
  const {format = 'html', language = 'de', reviews = new Map()} = options;
  const t = context(model, language);
  if (!['html','markdown'].includes(format) || !(reviews instanceof Map)) throw Error('Ungültige Berichtseinstellungen.');
  const isHtml = format === 'html';
  const counts = new Map();
  const workflows = new Map(states.map(key => [key, 0]));
  const cases = model.rows.map((row, i) => {
    const refs = evidenceFields(model, row, t);
    const state = reviewState(reviews.get(row.id)?.state);
    counts.set(row.status, (counts.get(row.status) || 0) + 1);
    workflows.set(state, workflows.get(state) + 1);
    const finding = row.status === 'confirmed' && model.kind === 'finding' ? ' · ' + t('requiredHeader') : '';
    return {heading: t('item') + ' ' + (i + 1) + finding, fields: [[t('decision'), t(row.status)], [t('review'), t(state)], ...refs]};
  });
  const header = 'AuthzLedger · ' + t('report');
  const source = [[t('category'), t(model.kind)], [t('source'), model.digest]];
  if (isDigest(model.scope)) source.push([t('scope'), model.scope]);
  const totals = [[t('count'), String(cases.length)], ...[...counts, ...workflows].map(([key, count]) => [t(key), String(count)])];
  const render = fields => isHtml
    ? '<dl>' + fields.map(([label,value]) => '<dt>' + html(label) + '</dt><dd><bdi>' + html(value) + '</bdi></dd>').join('') + '</dl>'
    : fields.map(([label,value]) => '- **' + label + '** · ' + value).join('\n');
  let text;
  if (isHtml) {
    text = '<!doctype html><html lang="' + language + '" dir="' + (language === 'ar' ? 'rtl' : 'ltr') + '"><head><meta charset="utf-8">' +
      '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1"><title>' + html(header) + '</title><style>' + reportCss + '</style></head><body>' +
      '<header><h1>' + html(header) + '</h1>' + render(source) + '</header><main><h2>' + html(t('executive')) + '</h2>' + render(totals) +
      '<p>' + html(t('boundaries')) + '</p><h2>' + html(t('appendix')) + '</h2>' +
      cases.map(c => '<article><h3>' + html(c.heading) + '</h3>' + render(c.fields) + '</article>').join('') + '</main><footer>' + rights + '</footer></body></html>\n';
  } else {
    text = ['# ' + header, render(source), '## ' + t('executive'), render(totals), t('boundaries'), '## ' + t('appendix'),
      ...cases.map(c => '### ' + c.heading + '\n\n' + render(c.fields)), rights].join('\n\n') + '\n';
  }
  return {text, mime: (isHtml ? 'text/html' : 'text/markdown') + ';charset=utf-8',
    filename: 'authzledger-report-' + model.digest.slice(0,12) + '-' + language + (isHtml ? '.html' : '.md')};
}

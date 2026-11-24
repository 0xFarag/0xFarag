// © Nasser Aldin Farag (0xFarag). All rights reserved.
const langs = ['de','en','fr','it','ar'];
const labels = {
  title:['Experiment und Belegprüfung','Experiment and evidence review','Expérience et revue des preuves','Esperimento e verifica delle prove','التجربة ومراجعة الأدلة'],
  intro:['Halten Sie eine Hypothese und eine Vergleichskontrolle fest. Beurteilen Sie später die bereits erfassten Belege.','Record a hypothesis and a comparison control. Review the captured evidence afterwards.','Consignez une hypothèse et un contrôle de comparaison, puis examinez les preuves recueillies.','Registra un’ipotesi e un controllo di confronto. Valuta poi le prove raccolte.','سجّل فرضية وضابطاً للمقارنة، ثم راجع الأدلة الملتقطة.'],
  newPlan:['Prüfplan erstellen','Create review plan','Créer un plan','Crea piano di verifica','إنشاء خطة مراجعة'],
  asset:['System im Prüfumfang','In-scope asset','Actif du périmètre','Risorsa nel perimetro','الأصل ضمن النطاق'],
  hypothesis:['Hypothese','Hypothesis','Hypothèse','Ipotesi','الفرضية'],
  expected:['Erwartete Beobachtung','Expected observation','Observation attendue','Osservazione attesa','الملاحظة المتوقعة'],
  control:['Geplante Vergleichskontrolle','Planned comparison control','Contrôle de comparaison prévu','Controllo di confronto previsto','ضابط المقارنة المخطط'],
  linked:['Zugehöriger Befund (optional)','Related finding (optional)','Constat associé (facultatif)','Riscontro collegato (facoltativo)','النتيجة المرتبطة (اختياري)'],
  none:['Keine Auswahl','None','Aucun','Nessuno','بدون اختيار'],
  savePlan:['Plan speichern','Save plan','Enregistrer le plan','Salva piano','حفظ الخطة'],
  choose:['Gespeicherten Prüfplan wählen','Select a saved plan','Choisir un plan enregistré','Seleziona un piano salvato','اختر خطة محفوظة'],
  empty:['Für diesen Fall liegt noch kein Prüfplan vor.','This case has no saved review plans.','Aucun plan enregistré pour ce dossier.','Nessun piano salvato per questo caso.','لا توجد خطة مراجعة محفوظة لهذه الحالة.'],
  history:['Plan und Revisionen','Plan and revisions','Plan et révisions','Piano e revisioni','الخطة والمراجعات'],
  plan:['Plan','Plan','Plan','Piano','خطة'],
  review:['Manuelle Beurteilung','Manual assessment','Appréciation manuelle','Valutazione manuale','تقييم يدوي'],
  add:['Beurteilung ergänzen','Add an assessment','Ajouter une appréciation','Aggiungi una valutazione','إضافة تقييم'],
  observed:['Beobachtung im Beleg','Observed in the evidence','Observation dans la preuve','Osservazione nella prova','الملاحظة في الدليل'],
  controlObserved:['Beobachtung in der Vergleichskontrolle','Observed in the comparison control','Observation du contrôle de comparaison','Osservazione nel controllo di confronto','الملاحظة في ضابط المقارنة'],
  outcome:['Beurteilung der Hypothese','Assessment of the hypothesis','Appréciation de l’hypothèse','Valutazione dell’ipotesi','تقييم الفرضية'],
  supports:['Belege stützen die Hypothese','Evidence supports the hypothesis','Les preuves étayent l’hypothèse','Le prove sostengono l’ipotesi','الأدلة تدعم الفرضية'],
  contradicts:['Belege widersprechen der Hypothese','Evidence contradicts the hypothesis','Les preuves contredisent l’hypothèse','Le prove contraddicono l’ipotesi','الأدلة تناقض الفرضية'],
  inconclusive:['Nicht entscheidbar','Inconclusive','Indéterminé','Non conclusivo','غير حاسم'],
  evidence:['Quellbeleg','Source evidence','Pièce source','Prova sorgente','دليل المصدر'],
  comparison:['Kontrollbeleg','Control evidence','Pièce de contrôle','Prova di controllo','دليل الضابط'],
  position:['Datensatznummer','Record number','Numéro de l’enregistrement','Numero del record','رقم السجل'],
  copy:['Belegreferenzen des Befunds übernehmen','Use the finding’s evidence references','Reprendre les références du constat','Usa i riferimenti del riscontro','استخدم مراجع أدلة النتيجة'],
  guidance:['Für eine Entscheidung sind zwei unterschiedliche Beobachtungen desselben Systems erforderlich. Fehlende Belege lassen sich als «Nicht entscheidbar» festhalten.','A decision requires two distinct observations for the same asset. Record missing evidence as inconclusive.','Une décision exige deux observations distinctes du même actif. En cas de preuves manquantes, choisissez « Indéterminé ».','Una decisione richiede due osservazioni distinte della stessa risorsa. Se mancano prove, scegli «Non conclusivo».','يتطلب الحكم ملاحظتين مختلفتين للأصل نفسه. عند نقص الأدلة اختر «غير حاسم».'],
  saveReview:['Revision speichern','Save revision','Enregistrer la révision','Salva revisione','حفظ المراجعة'],
  export:['Reproduzierbarkeitsnachweis als JSON','Export reproducibility record (JSON)','Exporter la fiche de reproductibilité (JSON)','Esporta scheda di riproducibilità (JSON)','تصدير سجل قابلية إعادة التحقق (JSON)'],
  identifiers:['Befund, Revision und Belegreferenzen','Finding, revision and evidence references','Constat, révision et références','Riscontro, revisione e riferimenti','النتيجة والمراجعة ومراجع الأدلة'],
  invalid:['Befund und Belege müssen zum System des Plans passen.','The finding and evidence must match the plan’s asset.','Le constat et les preuves doivent correspondre à l’actif prévu.','Il riscontro e le prove devono corrispondere alla risorsa del piano.','يجب أن تتطابق النتيجة والأدلة مع أصل الخطة.'],
  saved:['Revision gespeichert.','Revision saved.','Révision enregistrée.','Revisione salvata.','تم حفظ المراجعة.']
};

export function reviewText(key, lang) {
  return labels[key]?.[Math.max(0,langs.indexOf(lang))] || key;
}

export function lineage(records, planId) {
  const plan = records.find(item => item.kind === 'plan' && item.id === planId);
  if (!plan) return [];
  const relevant = records.filter(item => item.plan_id === plan.id);
  const children = new Map();
  for (const row of relevant) {
    if (row.id === plan.id) continue;
    if (children.has(row.parent_id)) throw new Error('Conflicting review revisions');
    children.set(row.parent_id,row);
  }
  const result = [plan], seen = new Set([plan.id]);
  while (children.has(result.at(-1).id)) {
    const last = result.at(-1), next = children.get(last.id);
    if (seen.has(next.id) || next.parent_sha256 !== last.sha256 || next.case_id !== plan.case_id || next.team_id !== plan.team_id) {
      throw new Error('Invalid review revision reference');
    }
    result.push(next); seen.add(next.id);
  }
  if (result.length !== relevant.length) throw new Error('Disconnected review revision');
  return result;
}

export function makeReviewExport(records, planId) {
  const revisions = lineage(records,planId);
  if (!revisions.length) throw new Error('Unknown review plan');
  const plan = revisions[0], last = revisions.at(-1);
  return {schema:'authzledger.reproducibility-record/v1',rights:'© Nasser Aldin Farag (0xFarag). All rights reserved.',signed:false,basis:'manual_review_of_existing_evidence',
    team_id:plan.team_id,case_id:plan.case_id,plan_id:plan.id,latest_revision_sha256:last.sha256,revisions};
}

function make(tag, text) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  return el;
}
function opt(value, label) {
  const element = make('option',label);
  element.value = value;
  return element;
}
function field(form, labelText, element, id) {
  const label = make('label',labelText);
  element.id = 'cr-' + id; element.name = id; label.htmlFor = element.id;
  form.append(label,element);
  return element;
}
function memo(form, label, name, max) {
  const e = make('textarea');
  e.required = true; e.maxLength = max; e.rows = 2; e.dir = 'auto';
  return field(form,label,e,name);
}
function action(form, label, submit = false) {
  const el = make('button',label);
  el.type = submit ? 'submit' : 'button'; el.className = submit ? 'primary' : 'secondary slim';
  form.append(el); return el;
}
function details(target, label, id) {
  const el = make('details');
  el.id = id; el.append(make('summary',label)); target.append(el); return el;
}
function group(target, title) {
  const form = make('form');
  target.append(form); form.setAttribute('aria-label',title); return form;
}
function picker(form, label, id, choices, selected) {
  const e = make('select');
  e.append(...choices.map(pair => opt(...pair)));
  if (Array.from(e.options).some(o => o.value === selected)) e.value = selected;
  return field(form,label,e,id);
}
function recordSelector(form, label, key, imports, t) {
  const group = make('fieldset'); group.append(make('legend',label)); form.append(group);
  const source = picker(group,t('evidence'),key+'-source', [['',t('none')],...imports.map(i=>[i.id,i.format+' · '+i.sha256.slice(0,16)])]);
  const entry = make('input'); entry.type = 'number'; entry.min = '1'; entry.step = '1'; entry.value = '1';
  field(group,t('position'),entry,key+'-number');
  const sync = () => {
    const imported = imports.find(x=>x.id === source.value);
    entry.disabled = !imported; entry.required = !!imported; entry.max = String(imported?.records || 1);
  };
  source.addEventListener('change',sync); sync();
  return {
    sync,
    requireSource(on) { source.required = on; },
    get() { return source.value ? {import_id:source.value,record:Number(entry.value)} : null; },
    set(ref) { source.value = ref?.import_id || ''; entry.value = String(ref?.record || 1); sync(); }
  };
}

export function createReviewPanel(container, {post, download, onError, reload}) {
  let key = '', selected = '', saved, drafts = new Map(), busy = false, generation = 0;
  let context;
  function clear() {
    key = ''; selected = ''; saved = undefined; drafts.clear(); busy = false; context = undefined;
    generation++; container.replaceChildren();
  }
  function capture() {
    for (const form of container.querySelectorAll('form[data-draft]')) {
      const data = {};
      for (const input of form.elements) if (input.name) data[input.name] = input.value;
      const prior = drafts.get(form.dataset.draft) || {};
      drafts.set(form.dataset.draft,{...prior, data, open:form.closest('details').open});
    }
  }
  function restore(form, id, sync) {
    form.dataset.draft = id;
    const draft = drafts.get(id);
    if (draft) {
      for (const input of form.elements) {
        if (input.name && Object.hasOwn(draft.data || {},input.name)) input.value = draft.data[input.name];
      }
      form.closest('details').open = !!draft.open;
    }
    if (sync) sync();
  }
  function submit(form, id, build) {
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (busy) return;
      const epoch = generation, caseKey = key;
      try {
        const payload = build();
        const signature = JSON.stringify(payload);
        const prior = drafts.get(id);
        const requestId = prior?.signature === signature ? prior.request : crypto.randomUUID();
        capture();
        drafts.set(id,{...drafts.get(id), signature, request:requestId});
        busy = true;
        for (const button of container.querySelectorAll('button[type=submit]')) button.disabled = true;
        const {record} = await post(payload,requestId);
        if (epoch !== generation || caseKey !== key) return;
        // Only delete the submitted draft; a case switch or another plan cannot inherit it.
        form.reset(); delete form.dataset.draft; drafts.delete(id);
        selected = record.plan_id; saved = true;
        const rows = context.records.filter(item=>item.id !== record.id);
        context = {...context,records:[...rows,record]};
        render(context);
      } catch (error) {
        if (epoch === generation) {
          if (error.status === 409) await reload().catch(() => {});
          if (epoch === generation) onError(error);
        }
      } finally {
        if (epoch === generation) {
          busy = false;
          for (const button of container.querySelectorAll('button[type=submit]')) button.disabled = false;
        }
      }
    });
  }
  function render(next) {
    if (!next) { clear(); return; }
    const nextKey = next.teamId + ':' + next.item.id;
    if (key !== nextKey) { clear(); key = nextKey; }
    else capture();
    context = next;
    const {item,imports,findings,records,lang,canPlan,canReview} = next;
    const t = k => reviewText(k,lang);
    const title = make('h3',t('title')); title.id = 'cr-heading';
    container.replaceChildren(title, make('p',t('intro')));
    const status = make('p',saved ? t('saved') : ''); status.setAttribute('role','status'); container.append(status);
    const plans = records.filter(row=>row.kind === 'plan');
    if (canPlan) {
      const panel = details(container,t('newPlan'),'cr-new');
      const form = group(panel,t('newPlan'));
      const asset = picker(form,t('asset'),'plan-asset',item.assets.map(x=>[x,x]));
      const hypothesis = memo(form,t('hypothesis'),'hypothesis',1000);
      const expected = memo(form,t('expected'),'expected',1500);
      const control = memo(form,t('control'),'control',1500);
      const finding = picker(form,t('linked'),'plan-finding',[]);
      const list = () => {
        const previous = finding.value;
        finding.replaceChildren(opt('',t('none')),...findings.filter(f=>f.asset===asset.value).map(f=>opt(f.id,f.title)));
        if ([...finding.options].some(o=>o.value===previous)) finding.value = previous;
      };
      list(); asset.addEventListener('change',list);
      action(form,t('savePlan'),true);
      restore(form,'plan');
      const restored = drafts.get('plan')?.data?.['plan-finding'];
      list(); if (restored && findings.some(f=>f.id===restored && f.asset===asset.value)) finding.value = restored;
      submit(form,'plan',()=>({kind:'plan',asset:asset.value,hypothesis:hypothesis.value,expected:expected.value,
        control:control.value,finding_id:finding.value || null}));
    }
    if (!plans.length) { container.append(make('p',t('empty'))); return; }
    if (!plans.some(p=>p.id===selected)) selected = plans[0].id;
    const chooser = picker(container,t('choose'),'selected',plans.map(p=>[p.id,p.hypothesis]),selected);
    chooser.addEventListener('change',()=>{selected = chooser.value; saved = false; render(context);});
    const history = lineage(records,selected);
    const plan = history[0], tip = history.at(-1);
    const heading = make('h4',t('history')); container.append(heading);
    const list = make('ol'); list.className = 'records'; container.append(list);
    for (const row of history) {
      const li = make('li'), block = make('details'), summary = make('summary',t(row.kind)+' · '+row.created_at);
      block.append(summary);
      const notes = row.kind === 'plan'
        ? [[t('asset'),row.asset],[t('hypothesis'),row.hypothesis],[t('expected'),row.expected],[t('control'),row.control]]
        : [[t('outcome'),t(row.outcome)],[t('observed'),row.observed],[t('controlObserved'),row.control_observed]];
      const dl = make('dl');
      for (const [name,value] of notes) {const dd=make('dd',value);dd.dir='auto';dl.append(make('dt',name),dd);}
      block.append(dl);
      const json = details(block,t('identifiers'),'cr-row-'+row.id);
      const code = make('pre',JSON.stringify({id:row.id,sha256:row.sha256,parent_sha256:row.parent_sha256,
        finding:row.finding,evidence:row.evidence,control_evidence:row.control_evidence},null,2));
      code.dir='ltr';json.append(code);li.append(block);list.append(li);
    }
    const exportButton = action(container,t('export')); exportButton.id = 'cr-export';
    exportButton.addEventListener('click',()=>download(makeReviewExport(context.records,plan.id),
      'authzledger-control-review-'+plan.id+'.json'));
    if (!canReview) return;
    const panel = details(container,t('add'),'cr-add');
    const form = group(panel,t('add'));
    const available = findings.filter(f=>f.asset===plan.asset);
    const finding = picker(form,t('linked'),'review-finding',[['',t('none')],...available.map(f=>[f.id,f.title])],tip.finding?.id);
    if (tip.finding) finding.disabled = true;
    const observed = memo(form,t('observed'),'observed',2000);
    const controlObserved = memo(form,t('controlObserved'),'control-observed',1500);
    const outcome = picker(form,t('outcome'),'outcome',['inconclusive','supports','contradicts'].map(x=>[x,t(x)]));
    form.append(make('p',t('guidance')));
    const first = recordSelector(form,t('evidence'),'main',imports,t);
    const second = recordSelector(form,t('comparison'),'comparison',imports,t);
    action(form,t('copy')).addEventListener('click',()=>{
      const linked = available.find(f=>f.id===finding.value);
      if (!linked) {status.textContent=t('invalid');return;}
      first.set(linked.evidence); second.set(linked.control?.reference);
    });
    action(form,t('saveReview'),true);
    const draftId = 'review:'+plan.id;
    function mode() {const on = outcome.value !== 'inconclusive'; first.requireSource(on); second.requireSource(on);}
    outcome.addEventListener('change',mode);
    restore(form,draftId,()=>{first.sync();second.sync();}); mode();
    if (tip.finding) finding.value = tip.finding.id;
    submit(form,draftId,()=>({kind:'review',parent_id:tip.id,parent_sha256:tip.sha256,finding_id:finding.value || null,
      observed:observed.value,control_observed:controlObserved.value,outcome:outcome.value,evidence:first.get(),control_evidence:second.get()}));
  }
  return {render,clear};
}

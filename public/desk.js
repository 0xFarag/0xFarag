// © Nasser Aldin Farag (0xFarag). All rights reserved.
(() => {
  'use strict';
  const triggers = [...document.querySelectorAll('[data-desk-open]')];
  if (!triggers.length) return;
  const translations = {
    de: {close:'Schliessen', intro:'Fragen zu Scope, Import, Controls, Retest und Signatur.',
      privacy:'Beim Senden erhält xAI die Produktfrage und den kurzen Gesprächsverlauf. Bitte nur öffentliche Produktfragen eingeben.',
      starters:['Wann ist ein Finding confirmed?', 'Was heisst not_retested?', 'Ersetzt das Nessus?'],
      field:'Deine Produktfrage', send:'Senden', wait:'Desk prüft …', answer:'Antwort', user:'Du',
      invalid:'Bitte eine Frage mit 3 bis 600 Zeichen eingeben.'},
    en: {close:'Close', intro:'Ask about scope, imports, controls, retests and signatures. Answers are in German.',
      privacy:'When you send, xAI receives your product question and recent conversation. Enter public product questions only.',
      starters:['When is a finding confirmed?', 'What does not_retested mean?', 'Does it replace Nessus?'],
      field:'Your product question', send:'Send', wait:'Desk is checking …', answer:'Answer', user:'You',
      invalid:'Enter a question with 3 to 600 characters.'},
    it: {close:'Chiudi', intro:'Domande su perimetro, importazione, controlli, retest e firma. Le risposte sono in tedesco.',
      privacy:'Quando invii la domanda, xAI riceve il testo e gli ultimi messaggi. Inserisci solo domande pubbliche sul prodotto.',
      starters:['Quando un finding è confirmed?', 'Cosa significa not_retested?', 'Sostituisce Nessus?'],
      field:'Domanda sul prodotto', send:'Invia', wait:'Verifica in corso …', answer:'Risposta', user:'Tu',invalid:'Inserisci una domanda da 3 a 600 caratteri.'},
    ar: {close:'إغلاق', intro:'أسئلة عن النطاق والاستيراد والضوابط وإعادة الاختبار والتوقيع. الإجابات بالألمانية.',
      privacy:'عند الإرسال تتلقى xAI سؤالك والمحادثة الأخيرة. أدخل أسئلة عامة عن المنتج فقط.',
      starters:['متى تكون النتيجة confirmed؟', 'ما معنى not_retested؟', 'هل يحل محل Nessus؟'],
      field:'سؤالك عن المنتج', send:'إرسال', wait:'جارٍ التحقق …', answer:'الإجابة', user:'أنت',invalid:'أدخل سؤالاً يتكون من 3 إلى 600 حرف.'},
    fr: {close:'Fermer', intro:'Posez vos questions sur le périmètre, les imports, les contrôles, les recontrôles et la signature. Réponses en allemand.',
      privacy:'À l’envoi, xAI reçoit votre question et les derniers échanges. Saisissez uniquement des questions publiques sur le produit.',
      starters:['Quand un constat est-il confirmed ?', 'Que signifie not_retested ?', 'Est-ce que cela remplace Nessus ?'],
      field:'Votre question sur le produit', send:'Envoyer', wait:'Vérification en cours …', answer:'Réponse', user:'Vous',
      invalid:'Saisissez une question de 3 à 600 caractères.'}
  };
  const localGuides = {
    de: {
      title: 'Produkthilfe ohne KI', unavailable: 'Der Desk ist hier gerade nicht erreichbar.',
      answers: ['Eine importierte Beobachtung wird erst mit passendem Scope, verfügbarem Budget, geschütztem Marker und wirksamen abhängigen Kontrollen bestätigt.',
        'Dieser ursprünglich bestätigte Fall wurde für die aktuelle Retest-Runde nicht ausgewählt. Ob der Fix wirkt, bleibt offen.',
        'Nessus liefert Scanergebnisse. AuthzLedger ergänzt solche Werkzeuge bei der Bewertung von Beobachtungen, beim Retest und bei der Übergabe.'],
      resources: ['Import öffnen', 'Proof Studio öffnen', 'Stabile Downloads']
    },
    en: {
      title: 'Product help without AI', unavailable: 'Desk is currently unavailable.',
      answers: ['An imported observation needs matching scope, available budget, a protected marker and effective dependent controls before it can be confirmed.',
        'This previously confirmed finding was not selected for this retest. Its fix is still unverified.',
        'Nessus provides scan results. AuthzLedger complements testing tools with evidence review, retests and handover.'],
      resources: ['Open import', 'Open Proof Studio', 'Stable downloads']
    },
    fr: {
      title: 'Aide produit sans IA', unavailable: 'Le Desk est momentanément indisponible.',
      answers: ['Pour confirmer une observation importée, il faut un périmètre correspondant, un budget disponible, un marqueur protégé et des contrôles associés efficaces.',
        'Ce constat confirmé précédemment n’a pas été sélectionné pour ce nouveau test. La correction reste à vérifier.',
        'Nessus fournit des résultats de scan. AuthzLedger complète les outils de test avec la revue des preuves, les nouveaux tests et la remise du dossier.'],
      resources: ['Ouvrir l’import', 'Ouvrir Proof Studio', 'Téléchargements stables']
    },
    it: {
      title: 'Guida al prodotto senza IA', unavailable: 'Il Desk è temporaneamente indisponibile.',
      answers: ['Per confermare un’osservazione importata servono un perimetro corrispondente, budget disponibile, un marcatore protetto e controlli associati efficaci.',
        'Questo rilievo già confermato non è stato selezionato per il retest attuale. La correzione resta da verificare.',
        'Nessus fornisce risultati di scansione. AuthzLedger integra gli strumenti di test con la verifica delle evidenze, i retest e la consegna.'],
      resources: ['Apri importazione', 'Apri Proof Studio', 'Download stabili']
    },
    ar: {
      title: 'مساعدة المنتج دون ذكاء اصطناعي', unavailable: 'خدمة Desk غير متاحة حالياً.',
      answers: ['يتطلب تأكيد الملاحظة المستوردة تطابق النطاق وتوفر الميزانية ووجود العلامة المحمية وفعالية الضوابط ذات الصلة.',
        'لم تُحدّد هذه النتيجة المؤكدة سابقاً لإعادة الاختبار الحالية. لا يزال الإصلاح بحاجة إلى التحقق.',
        'يقدم Nessus نتائج الفحص. يكمّل AuthzLedger أدوات الاختبار بمراجعة الأدلة وإعادة الاختبار وتسليم النتائج.'],
      resources: ['فتح الاستيراد', 'فتح Proof Studio', 'تنزيل الإصدارات المستقرة']
    }
  };
  const guidePaths = ['/import/', '/studio/', '/downloads/stable/'];
  function language() { return translations[document.documentElement.lang.slice(0,2).toLowerCase()] || translations.de; }
  let t=language(), statusKey='';
  const node = (tag, text) => { const el = document.createElement(tag); if (text) el.textContent = text; return el; };
  const button = (text) => { const el = node('button', text); el.type = 'button'; return el; };
  const panel = node('section');
  panel.id = 'authz-desk';
  panel.hidden = true;
  panel.dataset.state = 'idle';
  panel.setAttribute('aria-labelledby', 'authz-desk-title');
  const head = node('div'); head.className = 'desk-head';
  const title = node('h2','Desk'); title.id = 'authz-desk-title';
  const close = button(t.close); head.append(title, close);
  const choices = node('div'); choices.className = 'desk-choices';
  const form = node('form');
  const label = node('label',t.field); label.htmlFor = 'authz-desk-question';
  const input = node('textarea'); input.id = label.htmlFor; input.rows = 2; input.maxLength = 600; input.minLength = 3; input.required = true;
  const privacy = node('p',t.privacy); privacy.className = 'desk-privacy'; privacy.id = 'authz-desk-privacy';
  input.setAttribute('aria-describedby',privacy.id);
  const send = node('button',t.send); send.type = 'submit';
  const status = node('p'); status.setAttribute('role','status'); status.setAttribute('aria-live','polite'); status.className = 'desk-status';
  const log = node('div'); log.className = 'desk-history'; log.setAttribute('aria-live','polite');
  const rights = node('small','© Nasser Aldin Farag (0xFarag). All rights reserved.');
  const starters=t.starters.map((question,i) => {
    const choice = button(question);
    choice.addEventListener('click', () => {input.value=t.starters[i]; input.focus();});
    choices.append(choice); return choice;
  });
  const intro=node('p',t.intro);
  const guide = node('details');
  const guideHeading = node('summary');
  guide.append(guideHeading);
  const guideEntries = t.starters.map(() => {
    const entry = node('details');
    const heading = node('summary');
    const answer = node('p');
    entry.append(heading, answer);
    guide.append(entry);
    return {entry, heading, answer};
  });
  const guideLinks = node('ul');
  const links = guidePaths.map(() => {
    const link = node('a');
    const item = node('li');
    item.append(link);
    guideLinks.append(item);
    return link;
  });
  guide.append(guideLinks);
  function localGuide() {
    return localGuides[document.documentElement.lang.slice(0,2).toLowerCase()] || localGuides.de;
  }
  function translateGuide() {
    const copy = localGuide();
    guideHeading.textContent = copy.title;
    guideEntries.forEach(({heading, answer}, i) => {
      heading.textContent = t.starters[i];
      answer.textContent = copy.answers[i];
    });
    const locale = document.documentElement.lang.slice(0,2).toLowerCase();
    links.forEach((link, i) => {
      link.textContent = copy.resources[i];
      link.href = (Object.hasOwn(localGuides, locale) && locale !== 'de' ? '/' + locale : '') + guidePaths[i];
    });
  }
  translateGuide();
  form.append(label, input, privacy, send);
  panel.append(head, intro, choices, log, form, status, guide, rights);
  const footer = document.querySelector('body > footer');
  if (footer) footer.before(panel); else document.body.append(panel);
  let opener = triggers[0];
  function show(open) {
    panel.hidden = !open;
    for (const el of triggers) el.setAttribute('aria-expanded',String(open));
    if (open) {
      panel.scrollIntoView({block:'start'});
      input.focus({preventScroll:true});
    } else { opener.focus(); }
  }
  for (const trigger of triggers) {
    trigger.setAttribute('aria-controls',panel.id);
    trigger.setAttribute('aria-expanded','false');
    trigger.addEventListener('click', () => { opener = trigger; show(panel.hidden); });
  }
  close.addEventListener('click', () => show(false));
  panel.addEventListener('keydown', event => { if (event.key === 'Escape') show(false); });
  let context = [];
  function showTurns() {
    log.replaceChildren();
    for (const turn of context) {
      const item = node('p');
      item.append(node('strong',turn.role === 'user' ? t.user : t.answer), node('span',turn.content));
      log.append(item);
    }
  }
  window.addEventListener('authzlanguage',()=>{
    t=language(); intro.textContent=t.intro; privacy.textContent=t.privacy; close.textContent=t.close;
    label.textContent=t.field; send.textContent=t.send;
    starters.forEach((choice,i)=>choice.textContent=t.starters[i]);
    translateGuide();
    if(statusKey) status.textContent=statusKey === 'unavailable' ? localGuide().unavailable : t[statusKey];
    showTurns();
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (send.disabled) return;
    const question = input.value.trim();
    if ([...question].length < 3 || [...question].length > 600) {
      panel.dataset.state = 'error'; statusKey='invalid'; status.textContent=t.invalid; return;
    }
    panel.dataset.state = 'checking'; statusKey='wait'; status.textContent=t.wait; send.disabled = true;
    const starterIndex = t.starters.findIndex(starter => starter === question);
    try {
      const response = await fetch('/api/desk', {method:'POST', credentials:'omit', redirect:'error',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify({question,context:context.slice(-7)})});
      if (!response.ok) throw new Error('unavailable');
      const result = await response.json();
      if (typeof result.answer !== 'string' || !result.answer.trim()) throw new Error('invalid');
      context = [...context,{role:'user',content:question},{role:'assistant',content:result.answer}].slice(-8);
      showTurns(); if(input.value.trim()===question) input.value=''; statusKey=''; panel.dataset.state = 'answer'; status.textContent = '';
    } catch {
      panel.dataset.state = 'error'; statusKey='unavailable'; status.textContent=localGuide().unavailable;
      guide.open = true;
      if (starterIndex >= 0) guideEntries[starterIndex].entry.open = true;
    } finally { send.disabled = false; }
  });
})();

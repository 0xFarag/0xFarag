// © Nasser Aldin Farag (0xFarag). All rights reserved.
const rights = '© Nasser Aldin Farag (0xFarag). All rights reserved.';
const storageKey = 'authzledger.pilot-request.v1';
const translations = {
  de: ['Pilotanfrage', 'Organisation', 'Kontaktperson', 'Geschäftliche E-Mail', 'Guided hinzufügen (+ CHF 2’400)', '30 Tage · zwei Nutzer · ein autorisiertes Mandat', 'Zwei Sitzungen à 90 Minuten und eine Ergebniswerkstatt.', 'Bei der Abnahme prüft der Empfänger die Controls, den sichtbaren Status not_retested und das signierte Paket mit einem unabhängig bestätigten Schlüssel.', 'CHF 1’200 anrechenbar auf Team oder Consultancy innert 30 Tagen nach dokumentierter Pilotabnahme.', 'Anfrage lokal speichern und Angebotsbrief erstellen', 'Der Brief enthält die Nettopreise exklusive MwSt. und wird auf diesem Gerät gespeichert. Es erfolgt kein Versand.', 'Gesamtpreis', 'Angebotsbrief herunterladen', 'Lokal gespeicherte Anfrage löschen', 'Anfrage gelöscht.', 'Der Browser konnte die Anfrage nicht lokal speichern. Der Brief steht zum Download bereit.', 'Anfrage lokal gespeichert. Der Brief steht zum Download bereit.', 'Angebotsentwurf', 'Datum', 'Bitte verwenden Sie für ein verbindliches Angebot die Kontaktdaten Ihrer Organisation.'],
  en: ['Pilot enquiry', 'Organisation', 'Contact person', 'Work email', 'Add Guided (+ CHF 2,400)', '30 days · two users · one authorised engagement', 'Two 90-minute sessions and one results workshop.', 'At acceptance the recipient reviews the controls, the visible not_retested status and the signed package using an independently confirmed key.', 'CHF 1,200 credit towards Team or Consultancy within 30 days of documented pilot acceptance.', 'Save enquiry locally and prepare offer letter', 'The letter lists net prices excluding VAT and is saved on this device. Nothing is sent.', 'Total price', 'Download offer letter', 'Delete locally saved enquiry', 'Enquiry deleted.', 'Local storage is unavailable. The letter is ready to download.', 'Enquiry saved locally. The letter is ready to download.', 'Draft offer', 'Date', 'Please use your organisation’s contact details for a binding offer.'],
  it: ['Richiesta pilota','Organizzazione','Persona di contatto','E-mail professionale','Aggiungi Guided (+ CHF 2’400)','30 giorni · due utenti · un mandato autorizzato','Due sessioni da 90 minuti e un laboratorio di restituzione.','Al momento dell’accettazione il destinatario verifica i controlli, lo stato not_retested e il pacchetto firmato con una chiave confermata in modo indipendente.','Credito di CHF 1’200 su Team o Consultancy entro 30 giorni dall’accettazione documentata del pilota.','Salva localmente la richiesta e prepara la lettera d’offerta','La lettera riporta prezzi netti IVA esclusa e rimane su questo dispositivo. Non viene inviata.','Prezzo totale','Scarica la lettera d’offerta','Elimina la richiesta locale','Richiesta eliminata.','Archiviazione locale non disponibile. La lettera è pronta per il download.','Richiesta salvata localmente. La lettera è pronta per il download.','Bozza di offerta','Data','Per un’offerta vincolante, utilizza i recapiti della tua organizzazione.'],
  ar: ['طلب تجربة مدفوعة','المؤسسة','مسؤول الاتصال','البريد الإلكتروني للعمل','إضافة Guided (+ CHF 2’400)','30 يوماً · مستخدمان · مهمة واحدة مصرح بها','جلستان مدة كل منهما 90 دقيقة وورشة لمراجعة النتائج.','عند الاستلام يراجع المستلم الضوابط وحالة not_retested والحزمة الموقّعة بمفتاح تم التحقق منه بصورة مستقلة.','يُحتسب رصيد CHF 1’200 لخطة Team أو Consultancy خلال 30 يوماً من توثيق قبول التجربة.','حفظ الطلب محلياً وإعداد خطاب العرض','يشمل الخطاب الأسعار الصافية قبل ضريبة القيمة المضافة ويُحفظ على هذا الجهاز. لا يُرسل تلقائياً.','السعر الإجمالي','تنزيل خطاب العرض','حذف الطلب المحفوظ محلياً','تم حذف الطلب.','التخزين المحلي غير متاح. الخطاب جاهز للتنزيل.','حُفظ الطلب محلياً. الخطاب جاهز للتنزيل.','مسودة العرض','التاريخ','للحصول على عرض ملزم، استخدم بيانات الاتصال الخاصة بمؤسستك.'],
  fr: ['Demande de pilote', 'Organisation', 'Personne de contact', 'E-mail professionnel', 'Ajouter Guided (+ CHF 2’400)', '30 jours · deux utilisateurs · un mandat autorisé', 'Deux séances de 90 minutes et un atelier de restitution.', 'Lors de la réception, le destinataire vérifie les contrôles, le statut not_retested et le paquet signé avec une clé confirmée indépendamment.', 'Crédit de CHF 1’200 sur Team ou Consultancy dans les 30 jours suivant la réception documentée du pilote.', 'Enregistrer localement et préparer la lettre d’offre', 'La lettre indique les prix nets hors TVA et reste sur cet appareil. Aucun envoi.', 'Prix total', 'Télécharger la lettre d’offre', 'Effacer la demande locale', 'Demande effacée.', 'Le stockage local est indisponible. La lettre est prête à télécharger.', 'Demande enregistrée localement. La lettre est prête à télécharger.', 'Projet d’offre', 'Date', 'Pour une offre ferme, veuillez utiliser les coordonnées de votre organisation.']
};
function locale(lang) { return lang?.split('-')[0] in translations ? lang.split('-')[0] : 'de'; }
export function letter(data, lang, date) {
  const t=translations[locale(lang)];
  return [`AuthzLedger · ${t[17]}`, `${t[18]}: ${date}`, '', `${t[1]}: ${data.organisation}`, `${t[2]}: ${data.contact}`, `${t[3]}: ${data.email}`, '', 'Pilot · CHF 2’400', t[5], t[7], ...(data.guided ? ['Guided · CHF 2’400',t[6]] : []), `${t[11]} · CHF ${data.guided ? '4’800' : '2’400'}`, t[10], t[8], '', 'Nasser Aldin Farag · 0xFarag', rights, ''].join('\n');
}
export function mountPilot(root) {
  let lang=locale(document.documentElement.lang), t=translations[lang], savedLetter, statusIndex;
  const make=(tag,text)=>Object.assign(document.createElement(tag), text?{textContent:text}:{});
  const form=make('form'), inputs={}, status=make('p'), download=make('a',t[12]), forget=make('button',t[13]);
  const h=make('h3',t[0]), intro=make('p',t[10]), labels=[]; root.append(h, intro, form);
  status.setAttribute('role','status'); download.hidden=true; forget.type='button'; forget.hidden=true;
  let lastUrl='';
  ['organisation','contact','email','guided'].forEach((key,i)=>{
    const label=make('label',t[i+1]), field=make('input'); field.name=key; field.id='pilot-'+key; label.htmlFor=field.id;
    field.type=i===3?'checkbox':i===2?'email':'text'; field.required=i!==3; field.maxLength=150;
    if(i!==3) field.autocomplete=['organization','name','email'][i];
    inputs[key]=field; labels.push(label); form.append(label,field);
  });
  const submit=make('button',t[9]); submit.type='submit'; form.append(submit);root.append(status,download,forget);
  try {
    const saved=JSON.parse(localStorage.getItem(storageKey));
    if(saved && ['organisation','contact','email'].every(k=>typeof saved[k]==='string')) {
      for(const k of ['organisation','contact','email']) inputs[k].value=saved[k];
      inputs.guided.checked=saved.guided===true;forget.hidden=false;
    }
  }catch{}
  function clearOutput() {
    if(lastUrl) URL.revokeObjectURL(lastUrl); lastUrl='';download.hidden=true;download.removeAttribute('href');
  }
  function renderLetter(){
    clearOutput();
    if(!savedLetter) return;
    const date=new Intl.DateTimeFormat(lang+'-CH',{dateStyle:'long',timeZone:'Europe/Zurich'}).format(savedLetter.at);
    lastUrl=URL.createObjectURL(new Blob([letter(savedLetter.data,lang,date)],{type:'text/plain;charset=utf-8'}));
    download.href=lastUrl;download.download='AuthzLedger-Pilot.txt';download.hidden=false;
  }
  window.addEventListener('authzlanguage',()=>{
    lang=locale(document.documentElement.lang);t=translations[lang];
    h.textContent=t[0];intro.textContent=t[10];submit.textContent=t[9];download.textContent=t[12];forget.textContent=t[13];
    labels.forEach((label,i)=>label.textContent=t[i+1]);
    if(statusIndex!==undefined) status.textContent=t[statusIndex];
    if(savedLetter) renderLetter();
  });
  form.addEventListener('input',()=>{clearOutput();savedLetter=undefined;statusIndex=undefined;status.textContent='';});
  form.addEventListener('submit',event=>{
    event.preventDefault();if(!form.reportValidity()) return;
    const data={}; for(const k of ['organisation','contact','email']) { data[k]=inputs[k].value.trim(); if(!data[k]){inputs[k].focus();return;} }
    data.guided=inputs.guided.checked; clearOutput();
    let stored=true;try{localStorage.setItem(storageKey,JSON.stringify(data));}catch{stored=false;}
    savedLetter={data,at:new Date()}; renderLetter(); forget.hidden=false;statusIndex=stored?16:15;status.textContent=t[statusIndex];
  });
  forget.addEventListener('click',()=>{try{localStorage.removeItem(storageKey);}catch{} form.reset();clearOutput();savedLetter=undefined;forget.hidden=true;statusIndex=14;status.textContent=t[statusIndex];});
}
if(typeof document!=='undefined') for(const root of document.querySelectorAll('[data-pilot-form]')) mountPilot(root);

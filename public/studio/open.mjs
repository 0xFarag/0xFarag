// © Nasser Aldin Farag (0xFarag). All rights reserved.
const link=document.querySelector('#open-studio');
function updateLabel() {
  const lang=document.documentElement.lang.split('-')[0];
  link.textContent=({de:'Workbench öffnen',en:'Open Workbench',fr:'Ouvrir la Workbench',it:'Apri la Workbench',ar:'افتح مساحة العمل'})[lang] || 'Workbench öffnen';
}
updateLabel();
window.addEventListener('authzlanguage',updateLabel);
try {
  const response=await fetch('/api/workspace',{credentials:'omit',cache:'no-store'});
  const state=await response.json();
  if(response.ok && state.available===true && typeof state.origin==='string') {
    const url=new URL(state.origin);
    if(url.protocol==='https:' && url.origin===state.origin) {
      link.href=url.href;link.hidden=false;
    }
  }
} catch { /* The local installation and organisation-specific address remain available. */ }

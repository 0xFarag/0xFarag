// © Nasser Aldin Farag (0xFarag). All rights reserved.
(function () {
  const legacyLabSections = ['kontrolllabor', 'foederation', 'kandidatenpruefung', 'beweisfilm', 'status'];
  if (legacyLabSections.includes(location.hash.slice(1))) {
    const target = '/lab.html' + location.hash;
    location.replace(window.AuthzI18n?.url(target) ?? target);
    return;
  }
  // Same-page links keep the current document and its menu state.
  const menu = document.querySelector('.mobile-nav');
  menu.addEventListener('click', event => {
    const link = event.target.closest('a');
    if (link) menu.open = false;
  });
  menu.addEventListener('keydown', event => {
    if (event.key === 'Escape' && menu.open) {
      menu.open = false;
      menu.querySelector('summary').focus();
    }
  });
  const nav = document.querySelector('.proof-nav');
  const tabs = Array.from(nav.querySelectorAll('a'));
  const panels = tabs.map(tab => document.getElementById(tab.hash.slice(1)));
  nav.setAttribute('role', 'tablist');
  tabs.forEach((tab, i) => {
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-controls', panels[i].id);
    panels[i].setAttribute('role', 'tabpanel');
    panels[i].setAttribute('aria-labelledby', tab.id);
    panels[i].tabIndex = 0;
  });
  function select(index) {
    tabs.forEach((tab, i) => {
      tab.setAttribute('aria-selected', String(i === index));
      tab.tabIndex = i === index ? 0 : -1;
      panels[i].hidden = i !== index;
    });
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', event => { event.preventDefault(); select(index); });
    tab.addEventListener('keydown', event => {
      const forward = document.documentElement.dir === 'rtl' ? -1 : 1;
      const next = {ArrowRight: (index + tabs.length + forward) % tabs.length, ArrowLeft: (index + tabs.length - forward) % tabs.length,
                    Home: 0, End: tabs.length - 1}[event.key];
      if (next === undefined) return;
      event.preventDefault(); select(next); tabs[next].focus();
    });
  });
  const initial = panels.findIndex(p => '#' + p.id === location.hash);
  select(initial < 0 ? 0 : initial);
}());

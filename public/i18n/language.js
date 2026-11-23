// © Nasser Aldin Farag (0xFarag). All rights reserved.
(() => {
  'use strict';
  const {rows, routes, labels, names} = window.AuthzLocaleData;
  const languages = Object.keys(names);
  const aliases = new Map();
  for (const route of routes) {
    aliases.set(route, route);
    if (route.endsWith('/')) {
      aliases.set(route + 'index.html', route);
      aliases.set(route.slice(0, -1), route);
    }
  }
  const root = document.documentElement;
  const route = root.dataset.azRoute;
  const defaultLang = () => location.pathname.match(/^\/(de|en|fr|it|ar)(?=\/|$)/)?.[1];
  let current = defaultLang() || 'de';
  const byKey = new Map(rows.map(row => [row[0], row]));
  const textBindings = [];
  const attrBindings = [];
  const storageKey = 'authzledger.language';
  const normalized = value => value.trim().replace(/\s+/g, ' ');
  function t(source, params = {}) {
    if (typeof source !== 'string') return source;
    const row = byKey.get(normalized(source));
    const result = row ? source.match(/^\s*/)[0] + row[languages.indexOf(current)] + source.match(/\s*$/)[0] : source;
    return result.replace(/\{([A-Za-z0-9_]+)\}/g, (token, key) => Object.hasOwn(params, key) ? String(params[key]) : token);
  }

  function localUrl(value, lang = current) {
    const url = new URL(value, location.href);
    if (url.origin !== location.origin || !languages.includes(lang)) return url.href;
    const path = url.pathname.replace(/^\/(de|en|fr|it|ar)(?=\/|$)/, '') || '/';
    const target = aliases.get(path);
    return target === undefined ? url.href : '/' + lang + target + url.search + url.hash;
  }

  window.AuthzI18n = Object.freeze({get lang() { return current; }, t, url: localUrl});

  function updateLinks() {
    const picker = document.getElementById('az-language');
    if (!picker) return;
    picker.querySelector('[data-az-language-label]').textContent = labels[languages.indexOf(current)];
    picker.querySelector('[data-az-language-name]').textContent = names[current];
    for (const link of picker.querySelectorAll('[data-az-lang]')) {
      link.href = localUrl(location.href, link.dataset.azLang);
      if (link.dataset.azLang === current) link.setAttribute('aria-current', 'true');
      else link.removeAttribute('aria-current');
    }
    for (const link of document.querySelectorAll('a[data-az-link]')) {
      if (link.getAttribute('href').startsWith('#')) continue;
      const target = localUrl(link.href);
      link.href = current === 'de' && !defaultLang() ? target.replace(/^\/de(?=\/)/, '') : target;
    }
    const canonical = new URL((current === 'de' ? '' : '/' + current) + route, 'https://authzledger.com').href;
    document.querySelector('link[rel="canonical"]').href = canonical;
    const og = document.querySelector('meta[property="og:url"]');
    if (og) og.content = canonical;
  }

  function change(lang, {historyMode = null, remember = false} = {}) {
    if (!languages.includes(lang)) return;
    if (historyMode) history[historyMode](history.state, '', localUrl(location.href, lang));
    if (remember) {
      try { localStorage.setItem(storageKey, lang); } catch { /* Site storage is optional. */ }
    }
    const previous = current;
    current = lang;
    root.lang = lang === 'de' ? 'de-CH' : lang;
    root.dir = lang === 'ar' ? 'rtl' : 'ltr';
    if (previous !== lang) {
      for (const {node, index, left, right} of textBindings) {
        // Application code owns user input, source records and any replaced output.
        if (node.isConnected && normalized(node.data) === normalized(rows[index][languages.indexOf(previous)])) {
          node.data = left + rows[index][languages.indexOf(lang)] + right;
        }
      }
      for (const {el, key, index} of attrBindings) {
        if (el.isConnected && normalized(el.getAttribute(key) || '') === normalized(rows[index][languages.indexOf(previous)])) {
          el.setAttribute(key, rows[index][languages.indexOf(lang)]);
        }
      }
    }
    updateLinks();
    if (previous !== lang) window.dispatchEvent(new CustomEvent('authzlanguage', {detail: {lang, previous}}));
  }

  document.addEventListener('DOMContentLoaded', () => {
    const markers = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    function bind(node, index) {
      if (node?.nodeType === Node.TEXT_NODE && rows[index]) {
        textBindings.push({node, index, left: node.data.match(/^\s*/)[0], right: node.data.match(/\s*$/)[0]});
      }
    }
    while (markers.nextNode()) {
      const marker = markers.currentNode;
      const match = marker.data.match(/^az:(\d+)$/);
      if (match) bind(marker.nextSibling, Number(match[1]));
    }
    const title = document.querySelector('title[data-az-title]');
    if (title?.dataset.azTitle) bind(title.firstChild, Number(title.dataset.azTitle));
    for (const el of document.querySelectorAll('[data-az-attrs]')) {
      for (const entry of el.dataset.azAttrs.split(' ')) {
        const [key, index] = entry.split(':');
        attrBindings.push({el, key, index: Number(index)});
      }
    }

    const picker = document.getElementById('az-language');
    picker?.addEventListener('click', event => {
      const link = event.target.closest('[data-az-lang]');
      if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      change(link.dataset.azLang, {historyMode: defaultLang() === link.dataset.azLang ? null : 'pushState', remember: true});
      picker.open = false;
      picker.querySelector('summary').focus();
    });
    picker?.addEventListener('keydown', event => {
      if (event.key !== 'Escape' || !picker.open) return;
      picker.open = false;
      picker.querySelector('summary').focus();
    });
    document.addEventListener('click', event => {
      if (picker && !picker.contains(event.target)) picker.open = false;
    });
    window.addEventListener('popstate', () => change(defaultLang() || 'de'));
    window.addEventListener('hashchange', updateLinks);
    let saved;
    try { saved = localStorage.getItem(storageKey); } catch { /* Browser denied access. */ }
    if (!defaultLang() && languages.includes(saved) && saved !== current) {
      change(saved, {historyMode: 'replaceState'});
    } else {
      updateLinks();
    }
  }, {once: true});
})();

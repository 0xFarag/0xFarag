// © Nasser Aldin Farag (0xFarag). All rights reserved.
// Register UI messages explicitly. A replaced text node drops its registration.
(() => {
  'use strict';
  if (window.AuthzToolCopy) return;
  const messages = new WeakMap();
  const attributes = new WeakMap();
  const locale = () => window.AuthzI18n?.lang === 'de' || !window.AuthzI18n ? 'de-CH' : window.AuthzI18n.lang;

  function t(source, params = {}) {
    return window.AuthzI18n?.t(source, params) ?? source.replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(params, name) ? String(params[name]) : match);
  }

  function write(target, source, params = {}) {
    const render = typeof source === 'function' ? source : () => t(source, params);
    const text = document.createTextNode(render());
    messages.set(text, render);
    target.replaceChildren(text);
    target.dataset.toolCopy = '';
  }

  function attr(element, name, render) {
    if (!attributes.has(element)) attributes.set(element, new Map());
    attributes.get(element).set(name, render);
    element.dataset.toolCopy = '';
    element.setAttribute(name, render());
  }

  window.addEventListener('authzlanguage', () => {
    for (const target of document.querySelectorAll('[data-tool-copy]')) {
      for (const [name, render] of attributes.get(target) || []) target.setAttribute(name, render());
      for (const child of target.childNodes) {
        const render = messages.get(child);
        if (render) child.data = render();
      }
    }
  });
  window.AuthzToolCopy = Object.freeze({t, write, attr, locale});
})();

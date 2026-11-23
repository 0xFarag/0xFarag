// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
(async () => {
  const el = id => document.getElementById(id);
  const message = text => { el('status').textContent = text; };
  const plan = new URL(location.href).searchParams.get('plan');
  const plans = new Map([['solo', ['Solo', 'CHF 1’200 / Jahr']], ['team', ['Team', 'CHF 4’800 / Jahr']]]);
  const isStorefront = ['authzledger.com', 'www.authzledger.com', 'authzledger.vercel.app'].includes(location.hostname);
  const page = document.body.dataset.page;
  let attempt, stripeLoader;
  function loadStripe() {
    if (!stripeLoader) {
      stripeLoader = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://js.stripe.com/endive/stripe.js';
        const failed = () => { script.remove(); reject(new Error('stripe_load')); };
        const timeout = setTimeout(failed, 15000);
        script.onload = () => {
          clearTimeout(timeout);
          if (typeof window.Stripe === 'function') resolve(window.Stripe);
          else failed();
        };
        script.onerror = () => { clearTimeout(timeout); failed(); };
        document.head.append(script);
      }).catch(error => { stripeLoader = null; throw error; });
    }
    return stripeLoader;
  }
  async function jsonRequest(path, options = {}) {
    const response = await fetch(path, {
      cache: 'no-store', credentials: 'same-origin', redirect: 'error',
      signal: AbortSignal.timeout(15000), ...options
    });
    if (!response.ok) throw new Error(response.status === 429 ? 'rate_limited' : 'unavailable');
    return response.json();
  }
  function accessible(status) {
    return status.state === 'live' || (status.state === 'test' && !isStorefront);
  }
  if (page === 'kasse') {
    if (!plans.has(plan)) {
      message('Bitte wählen Sie zuerst Solo oder Team auf der Tarifseite.');
      return;
    }
    const [name, price] = plans.get(plan);
    el('plan-title').textContent = 'AuthzLedger ' + name;
    el('price').textContent = price;
    el('price').hidden = false;
  }
  let status;
  try {
    status = await jsonRequest('/api/billing-status');
    if (!status || !['offline', 'test', 'live'].includes(status.state)) throw new Error('invalid_status');
  } catch {
    message('Die Verfügbarkeit ist momentan nicht abrufbar. Laden Sie die Seite erneut oder kontaktieren Sie Nasser Aldin Farag.');
    return;
  }
  if (page === 'abos') {
    const labels = accessible(status)
      ? [...plans].filter(([key]) => status.checkout?.[key] === true).map(([, value]) => value[0])
      : [];
    let notice = 'Aktuell erhalten Sie eine persönliche Offerte. Der Online-Abschluss ist noch nicht freigeschaltet.';
    if (labels.length) notice = status.state === 'test' ? 'Testumgebung für die Tarifauswahl.' : 'Online erhältlich: ' + labels.join(' und ') + '.';
    message(notice);
    return;
  }
  if (page === 'konto') {
    if (new URL(location.href).searchParams.get('status') === 'unavailable') {
      message('Das Kundenportal ist momentan nicht erreichbar. Versuchen Sie es später erneut oder nutzen Sie den persönlichen Kontakt.');
      return;
    }
    if (!accessible(status) || status.portal !== true) {
      message('Der Zugang zum Kundenportal ist noch nicht freigeschaltet. Fragen zur Abrechnung beantwortet Nasser Aldin Farag persönlich.');
      return;
    }
    const portal = el('portal');
    portal.href = '/api/customer-portal';
    portal.hidden = false;
    message(status.state === 'test' ? 'Testumgebung für das Kundenportal.' : 'Die Anmeldung öffnet sich im geschützten Stripe-Kundenportal.');
    return;
  }
  const publishable = typeof status.publishableKey === 'string' && status.publishableKey.startsWith('pk_' + status.state + '_');
  if (!accessible(status) || status.checkout?.[plan] !== true || !publishable) {
    message('Der Online-Abschluss ist noch nicht freigeschaltet. Sie können diese Lizenz per persönlicher Offerte anfragen.');
    return;
  }
  message(status.state === 'test' ? 'Testumgebung. Verwenden Sie ausschliesslich Stripe-Testdaten.' : 'Das Zahlungsformular zeigt den fälligen Betrag vor dem verbindlichen Abschluss.');
  const start = el('checkout-start');
  start.hidden = false;
  start.addEventListener('click', async () => {
    if (start.disabled) return;
    start.disabled = true;
    message('Das Zahlungsformular wird geladen …');
    let checkout;
    try {
      attempt ||= crypto.randomUUID();
      const Stripe = await loadStripe();
      const stripe = Stripe(status.publishableKey, { locale: 'de' });
      checkout = await stripe.createEmbeddedCheckoutPage({
        fetchClientSecret: async () => {
          const result = await jsonRequest('/api/create-checkout', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ plan, requestId: attempt })
          });
          if (typeof result.clientSecret !== 'string' || !result.clientSecret) throw new Error('unavailable');
          return result.clientSecret;
        }
      });
      checkout.mount('#embedded');
      start.hidden = true;
      message(status.state === 'test' ? 'Testumgebung. Verwenden Sie ausschliesslich Stripe-Testdaten.' : 'Füllen Sie das Zahlungsformular von Stripe aus.');
    } catch (error) {
      if (checkout) checkout.destroy();
      start.disabled = false;
      message(error.message === 'rate_limited'
        ? 'Zu viele Versuche. Warten Sie einen Moment, bevor Sie das Zahlungsformular erneut öffnen.'
        : 'Das Zahlungsformular konnte nicht geöffnet werden. Versuchen Sie es erneut oder fordern Sie eine Offerte an.');
    }
  });
})();

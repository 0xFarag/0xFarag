// © Nasser Aldin Farag (0xFarag). All rights reserved.
export function tr(source, parameters = {}) {
  return window.AuthzI18n?.t(source, parameters) ?? source.replace(/\{(\w+)\}/g,
    (match, key) => Object.hasOwn(parameters, key) ? parameters[key] : match);
}

export function indexLocator(value) {
  const match = /^(Zeile|Datensatz) ([1-9]\d{0,6})$/u.exec(value);
  if (!match) return value;
  return tr(match[1] === 'Zeile' ? 'Zeile {n}' : 'Datensatz {n}',{n:match[2]});
}
export function sourceLabel(model,row) {
  // These fields are supplied by the imported author, rather than source-type labels.
  if (model.kind === 'blue' || (model.kind === 'inventory' && row.title === 'Ausgeschlossenes Artefakt')) return row.source;
  return tr(row.source);
}

export function rowTitle(model, row) {
  if (model.kind === 'manual') return row.title;
  if (model.kind === 'retest') return tr('Retest-Fall {id}', {id:row.title.slice('Retest-Fall '.length)});
  if (row.title.startsWith('ZAP-Regel ')) return tr('ZAP-Regel {id}', {id:row.title.slice('ZAP-Regel '.length)});
  if (row.title.startsWith('Signalfenster ')) return tr('Signalfenster {id}', {id:row.title.slice('Signalfenster '.length)});
  if (row.reference) {
    const sourcePart = row.source + ' · ' + row.reference.locator;
    const suffix = row.title.slice(sourcePart.length);
    return sourceLabel(model, row) + ' · ' + indexLocator(row.reference.locator) + (suffix === ' · ohne Hostbezug' ? ' · ' + tr('Kein Hostbezug') : suffix);
  }
  return tr(row.title);
}

export function rowSummary(model, row) {
  if (model.kind === 'manual') return row.summary;
  if (row.reference) return tr('Der Belegindex verweist auf eine Beobachtung aus {source}.', {source:sourceLabel(model, row)});
  if (row.signalCoverage?.eligible) return tr('{linked} von {eligible} passenden Ereignissen sind einem Alarm zugeordnet.', row.signalCoverage);
  const http = /^Die Quelle meldet HTTP (\d+)\.$/.exec(row.summary);
  if (http) return tr('Die Quelle meldet HTTP {status}.', {status:http[1]});
  const service = /^Gemeldeter Zustand: (.+)\.$/.exec(row.summary);
  if (service) return tr('Gemeldeter Zustand: {status}.', {status:service[1]});
  const reason = /^Auslassungsgrund der Quelle: (.+)\.$/.exec(row.summary);
  if (reason) return tr('Auslassungsgrund der Quelle: {reason}.', {reason:reason[1]});
  return tr(row.summary);
}

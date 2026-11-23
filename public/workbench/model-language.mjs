// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {tr} from './language.mjs';

// Model errors interpolate the name of a schema field, never the field's uploaded value.
const errorTemplates = [
  [/^Ungültige Anzahl Einträge für «([^»]+)» \(erlaubt (\d+) bis (\d+)\)\.$/u,'Ungültige Anzahl Einträge für «{field}» (erlaubt {min} bis {max}).'],
  [/^Ungültiger Text für «([^»]+)»\.$/u,'Ungültiger Text für «{field}».'],
  [/^Ungültige ID für «([^»]+)»\.$/u,'Ungültige ID für «{field}».'],
  [/^Ungültiger SHA-256-Wert für «([^»]+)»\.$/u,'Ungültiger SHA-256-Wert für «{field}».'],
  [/^Mehrdeutige Kennung in «([^»]+)»\.$/u,'Mehrdeutige Kennung in «{field}».'],
  [/^Der Nenner für «([^»]+)» stimmt nicht\.$/u,'Der Nenner für «{field}» stimmt nicht.']
];
export function normalizedText(message) {
  for (const [pattern,template] of errorTemplates) {
    const match = pattern.exec(message);
    if (match) return tr(template,{field:tr(match[1]),min:match[2],max:match[3]});
  }
  return tr(message);
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
export function detailValue(model,row,detail) {
  const {label,value} = detail;
  if (model.kind === 'retest' && row.status === 'not_retested' && label === 'Aktueller Befund') return tr(value);
  if (model.kind === 'evidence_index') {
    if (label === 'Quellposition') return indexLocator(value);
    if (label === 'Asset-ID' && value === 'Kein Hostbezug') return tr(value);
    return value;
  }
  if (model.kind !== 'blue') return value;
  if (['Abdeckung im Bericht','Retest-Status laut Quelle','Belegdaten','Aussagegrenze'].includes(label)) return tr(value);
  if (label === 'Passende Ereignisse ohne Alarm' && row.signalCoverage.linked === row.signalCoverage.eligible) return tr('Keine');
  if (label === 'Ursprünglicher Retest-Umfang') {
    const match = /^(\d+) Befunde, davon (\d+) ausgelassen$/u.exec(value);
    if (match) return tr('{total} Befunde, davon {skipped} ausgelassen',{total:match[1],skipped:match[2]});
  }
  if (label === 'Zeitraum') {
    const match = /^(\S+) bis (\S+) \(Ende exklusiv\)$/u.exec(value);
    if (match) return tr('{from} bis {until} (Ende exklusiv)',{from:match[1],until:match[2]});
  }
  return value;
}

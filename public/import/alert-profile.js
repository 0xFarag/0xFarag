// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const AuthzFalcoProfile = (() => {
  // Falco stable rule, documented at https://falcosecurity.github.io/rules/
  const rule = 'Redirect STDOUT/STDIN to Network Connection in Container';
  const definition = {
    label: 'Falco',
    format: 'JSONL · Falco',
    accept: '.json,.jsonl,.ndjson',
    hint: 'Importieren Sie Falco-JSON-Ereignisse der Regel «Redirect STDOUT/STDIN to Network Connection in Container». Eine Meldung zeigt eine mögliche Reverse Shell an. Angezeigt werden Zeitpunkt und Priorität.'
  };
  const sample = JSON.stringify({time:'2026-01-15T10:00:00.123456789Z', rule, priority:'Notice',
    hostname:'training.example', source:'syscall', output_fields:{}});
  const invalid = 'Erwartet werden JSON-Zeilen mit der unterstützten Falco-Regel, UTC-Zeitpunkt und gültiger Priorität.';
  const priorities = ['emergency','alert','critical','error','warning','notice','informational','debug'];
  function utc(value) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) return false;
    const second = value.slice(0,19);
    const date = new Date(second + 'Z');
    return Number.isFinite(date.getTime()) && date.toISOString().slice(0,19) === second;
  }
  function detect(event) { return event?.rule === rule ? 'falco' : null; }
  function parse(input, add, {json, requireThat, object}) {
    let count = 0;
    for (const [i,line] of input.split(/\r?\n/).entries()) {
      if (!line.trim()) continue;
      const event = json(line);
      const priority = typeof event?.priority === 'string' ? event.priority.toLowerCase() : '';
      requireThat(detect(event) && (event.source === undefined || event.source === 'syscall') &&
        priorities.includes(priority) && utc(event.time) && object(event.output_fields), invalid);
      const host = event.hostname ?? '';
      requireThat(typeof host === 'string' && host.length <= 253 && (!host || /^[A-Z0-9_.:-]+$/i.test(host)), invalid);
      // The adapter hashes the raw row for exact duplicate comparison and drops the raw input.
      // Falco events have no stable cross-export ID. Leave the comparison identity unset.
      add(host, priority + ' · ' + event.time, line.trim(), null, 'Zeile ' + (i+1));
      count++;
    }
    requireThat(count > 0, invalid);
  }
  return Object.freeze({definitions:{falco:definition}, samples:{falco:sample}, detect, parse});
})();

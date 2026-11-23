// ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
const sha256 = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const hasId = value => typeof value === 'string' && value.trim() === value && value.length > 0;
const contextFields = new Set(['detail:Snapshot', 'detail:Retest-Ausführung']);
const kinds = new Set(['finding', 'retest', 'inventory']);

function indexRows(rows) {
  if (!Array.isArray(rows)) return null;
  const indexed = new Map();
  for (const row of rows) {
    if (!row || !hasId(row.id) || indexed.has(row.id)) return null;
    indexed.set(row.id, row);
  }
  return indexed;
}

// Fields chosen by the reader are comparable across files. Technical data that
// the reader did not project cannot acquire meaning through this comparison.
function rowFields(row) {
  const fields = new Map([
    ['title', {label:'Bezeichnung', values:[row.title]}],
    ['status', {label:'Status der Quelle', values:[row.status]}],
    ['source', {label:'Quelle', values:[row.source]}],
    ['summary', {label:'Einordnung', values:[row.summary]}]
  ]);
  for (const detail of row.details) {
    const key = 'detail:' + detail.label;
    if (!fields.has(key)) fields.set(key, {label:detail.label, values:[]});
    fields.get(key).values.push(detail.value);
  }
  // Detail order within an equivalent label is presentation, not identity.
  for (const field of fields.values()) field.values.sort();
  return fields;
}

function fieldChanges(left, right) {
  const from = rowFields(left);
  const to = rowFields(right);
  const differences = [];
  for (const key of new Set([...from.keys(), ...to.keys()])) {
    const oldField = from.get(key);
    const newField = to.get(key);
    const before = oldField?.values ?? [];
    const after = newField?.values ?? [];
    if (before.length !== after.length || before.some((value, i) => value !== after[i])) {
      differences.push({field:key, label:(oldField || newField).label, before, after});
    }
  }
  return differences;
}

export function compareProjections(before, after) {
  const leftCount = Array.isArray(before?.rows) ? before.rows.length : null;
  const rightCount = Array.isArray(after?.rows) ? after.rows.length : null;
  const blocked = (reason, message) => ({comparable:false, reason, message, leftCount, rightCount});
  if (!before || !after) return blocked('missing', 'Wählen Sie zwei Belegstände.');
  // A native SOC report carries source digests, but omits the original retest
  // and signal data. Comparing declared IDs would allow unrelated reports to
  // appear bound merely by copying the metadata.
  if (before.kind === 'blue' && after.kind === 'blue') {
    return blocked('blue_source_binding', 'SOC-Berichte lassen sich hier einzeln prüfen. Für einen gebundenen Standvergleich fehlen der ursprüngliche Retest und die Signaldatei. Die Hashangaben im Bericht allein belegen keine gemeinsame Herkunft.');
  }
  if (!kinds.has(before.kind) || before.kind !== after.kind) {
    return blocked('kind', 'Die Quellentypen unterscheiden sich oder werden für einen Vergleich nicht unterstützt.');
  }
  if (!hasId(before.assessment) || before.assessment !== after.assessment) {
    return blocked('assessment', 'Die Assessment-IDs fehlen oder stimmen nicht überein.');
  }
  if (!sha256(before.scope) || before.scope !== after.scope) {
    return blocked('scope', 'Der gemeinsame Scope ist anhand der beiden Fingerabdrücke nicht belegbar.');
  }
  if (before.kind === 'retest' && (!sha256(before.baselineExecution) || before.baselineExecution !== after.baselineExecution)) {
    return blocked('baseline', 'Die Retests haben keine nachweislich gemeinsame Baseline-Ausführung.');
  }
  if (!sha256(before.digest) || !sha256(after.digest)) {
    return blocked('digest', 'Mindestens einer der beiden Datei-Fingerabdrücke fehlt.');
  }

  const left = indexRows(before.rows);
  const right = indexRows(after.rows);
  if (!left || !right) return blocked('identity', 'Mindestens ein Stand enthält fehlende oder mehrdeutige Fall-IDs.');
  const rows = [];
  const counts = {same:0, changed:0, contextOnly:0, leftOnly:0, rightOnly:0, unbound:0};
  for (const id of new Set([...left.keys(), ...right.keys()])) {
    const previous = left.get(id) ?? null;
    const next = right.get(id) ?? null;
    let state;
    let changes = [];
    if (!previous) state = 'rightOnly';
    else if (!next) state = 'leftOnly';
    else if (!sha256(previous.binding) || previous.binding !== next.binding) state = 'unbound';
    else {
      changes = fieldChanges(previous, next);
      if (!changes.length) state = 'same';
      else if (changes.every(change => contextFields.has(change.field))) state = 'contextOnly';
      else state = 'changed';
    }
    rows.push({id, state, before:previous, after:next, changes});
    counts[state]++;
  }
  return {comparable:true, leftCount, rightCount, sameFile:before.digest === after.digest, counts, rows};
}

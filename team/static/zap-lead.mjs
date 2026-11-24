// © Nasser Aldin Farag (0xFarag). All rights reserved.
export function zapRule(row, translate) {
  const fields = ['ZAP ' + (row.alert_ref || row.rule_id || '')];
  if (Number.isInteger(row.riskcode)) fields.push(translate('zapRisk') + ' ' + row.riskcode + '/3');
  if (Number.isInteger(row.confidence)) fields.push(translate('zapConfidence') + ' ' + row.confidence + '/4');
  return fields.join(' · ').trim();
}

export function createZapLead(document, translate) {
  const panel = document.getElementById('zap-link');
  const source = document.getElementById('zap-source');
  const record = document.getElementById('zap-record');
  let available = [];
  function option(value, text) {
    const item = document.createElement('option');
    item.value = value;
    item.textContent = text;
    return item;
  }
  function positions(prior = '') {
    const entries = available.find(item => item.id === source.value)?.entries || [];
    const options = entries.map(row => option(String(row.record),
      '#' + row.record + ' · ' + zapRule(row, translate) + ' · ' + row.fingerprint.slice(0, 12)));
    record.replaceChildren(option('', translate('choose')), ...options);
    record.value = entries.some(row => String(row.record) === prior) ? prior : '';
    record.disabled = !source.value || panel.hidden;
    record.required = !record.disabled;
  }
  source.addEventListener('change', () => positions());
  return {
    refresh(imports, fresh) {
      const prev = fresh ? '' : source.value, position = fresh ? '' : record.value;
      available = imports.filter(item => item.format === 'zap' && item.records > 0);
      source.replaceChildren(option('', translate('noZapLink')),
        ...available.map(item => option(item.id, 'ZAP · ' + item.sha256.slice(0, 16))));
      source.value = available.some(item => item.id === prev) ? prev : '';
      positions(position);
    },
    mode(confirmed) {
      panel.hidden = !confirmed || !available.length;
      source.disabled = panel.hidden;
      record.disabled = panel.hidden || !source.value;
      record.required = !record.disabled;
    },
    reference() {
      if (panel.hidden || !source.value) return {};
      return {zap_lead: {import_id: source.value, record: Number(record.value)}};
    },
  };
}

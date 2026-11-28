// © Nasser Aldin Farag (0xFarag). All rights reserved.
const order = {critical:0, high:1};

export function scannerPriorities(report) {
  const hosts = new Set(report?.scope?.hosts);
  const rows = (report?.findings || []).filter(({status,observation}) =>
    status !== 'out_of_scope' && hosts.has(observation.host) &&
    (observation.source === 'Nessus' || observation.source === 'Nuclei') &&
    Object.hasOwn(order,observation.severity));
  return rows.sort((a,b) => {
    const diff = order[a.observation.severity] - order[b.observation.severity];
    if (diff) return diff;
    for (const key of ['host','source','rule','id']) {
      if (a.observation[key] < b.observation[key]) return -1;
      if (a.observation[key] > b.observation[key]) return 1;
    }
    return 0;
  });
}

// ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
(() => {
  const picker = document.getElementById('signal-case');
  const status = document.getElementById('signal-status');
  const note = document.getElementById('signal-note');
  const download = document.getElementById('signal-download');
  const names = {
    observed: ['Signal und Alarm zugeordnet', 'Die synthetische Regelmeldung verweist auf das erwartete Ereignis innerhalb des Zeitfensters.'],
    telemetry_only: ['Ereignis vorhanden, Alarm offen', 'Die passende Beobachtung ist vorhanden. Für diese Regel liegt kein zugehöriger Alarm vor.'],
    unavailable: ['Telemetrie fehlt', 'Diese Quelle enthält für das Beispiel keine Ereignisse. Die Wirkung der Erkennung bleibt offen.'],
    incomparable: ['Andere Belegzuordnung', 'Die Quelle enthält Daten, deren Mandats- oder Zeitbindung die Erwartung nicht erfüllt.']
  };
  async function initialise() {
    const [sourceResponse, fixtureResponse] = await Promise.all([fetch('proof/mixed-c-result.json'),fetch('proof/control-lab.json')]);
    if (!sourceResponse.ok || !fixtureResponse.ok) throw Error('source unavailable');
    const source = await sourceResponse.arrayBuffer();
    const fixture = await fixtureResponse.json();
    const fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', source)), n => n.toString(16).padStart(2,'0')).join('');
    const original = JSON.parse(new TextDecoder().decode(source));
    const expect = fixture.expectation;
    const finding = original.transitions.find(row => row.finding_id === expect.finding);
    if (fixture.anchor_sha256 !== fingerprint || expect.assessment !== original.assessment_id || expect.scope !== original.scope_digest || !finding) throw Error('anchor mismatch');
    let href;
    function show() {
      const sample = fixture.controls[picker.value];
      const matching = sample.events.filter(entry => ['assessment','scope','finding','source'].every(key => entry[key] === expect[key]) && Date.parse(entry.at) >= Date.parse(expect.from_utc) && Date.parse(entry.at) < Date.parse(expect.until_utc));
      const alert = sample.alerts.find(a => a.rule === expect.rule && matching.some(e => e.event === a.event));
      const verdict = alert ? 'observed' : matching.length ? 'telemetry_only' : sample.events.length ? 'incomparable' : 'unavailable';
      [status.textContent,note.textContent] = names[verdict];
      if (href) URL.revokeObjectURL(href);
      const record = {schema:'authzledger.lab.ir-export/v1', rights:fixture.rights, synthetic:true, signed:false, assessment:expect.assessment, scope:expect.scope, expected:expect, example:picker.value, input:sample, control_status:verdict, retest_status:finding.status, finding_id:finding.finding_id, coverage:original.transitions.map(({finding_id,status})=>({finding_id,status})), source_file:'mixed-c-result.json', source_sha256:fingerprint, snapshot_digest:original.snapshot_digest};
      href = URL.createObjectURL(new Blob([JSON.stringify(record,null,2)+'\n'],{type:'application/json'}));
      download.href=href; download.hidden=false;
    }
    picker.disabled=false;picker.addEventListener('change',show);show();
  }
  initialise().catch(()=>{status.textContent='Belegquelle nicht verifiziert';note.textContent='Die Quelldateien konnten nicht geladen oder ihrem Digest zugeordnet werden.';download.hidden=true;picker.disabled=true;});
})();

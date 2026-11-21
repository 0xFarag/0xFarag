// © Nasser Aldin Farag (0xFarag). All rights reserved.
(() => {
  'use strict';

  const directory = 'proof/v1.5.0/';
  const receiptDigest = 'ff96a568dc7700d12626ccaf0c269556d5c11bd4c05e27b4cdd55cab2a65c9a9';
  const keyFingerprint = 'f38decf76b93bfc01a132a504195f305e217f6d9ce8a29628b096abc68b40696';
  const domain = 'AuthzLedger:EvidenceBundle:Ed25519:v1\n';
  const decoder = new TextDecoder();
  const encode = new TextEncoder();
  const select = document.getElementById('finding-select');
  const button = document.getElementById('verify');
  const controls = document.getElementById('signature-controls');
  const note = document.getElementById('verification-note');

  async function read(file) {
    const response = await fetch(directory + file);
    if (!response.ok) throw new Error('missing file');
    return new Uint8Array(await response.arrayBuffer());
  }

  async function sha256(bytes) {
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  function decode64(value) {
    return Uint8Array.from(atob(value), char => char.charCodeAt(0));
  }

  async function loadFindings() {
    const bytes = await read('receipt.json');
    if (await sha256(bytes) !== receiptDigest) throw new Error('receipt mismatch');
    const receipt = JSON.parse(decoder.decode(bytes));
    const records = receipt.transitions;
    const ledger = receipt.execution_ledger;
    document.getElementById('budget').textContent =
      'Demolauf: ' + ledger.dispatched_total + ' von ' + ledger.approved_total + ' freigegebenen Operationen ausgeführt.';
    select.replaceChildren(...records.map((record, index) => {
      const option = document.createElement('option');
      option.value = record.finding_id;
      option.textContent = 'Befund ' + (index + 1) + ' · ' + record.status;
      return option;
    }));

    function renderFinding() {
      const record = records.find(entry => entry.finding_id === select.value);
      document.getElementById('finding-state').textContent = record.status;
      document.getElementById('finding-note').textContent = record.status === 'fix_verified'
        ? 'Der Retest ordnet dem ursprünglichen Befund einen neuen Befund-Digest zu.'
        : 'Für diesen Befund fehlt ein neuer Retest. Er bleibt als offen sichtbar.';
      document.getElementById('finding-id').textContent = record.finding_id;
      document.getElementById('finding-baseline').textContent = record.baseline_finding_digest;
      document.getElementById('finding-current').textContent = record.current_finding_digest || 'Kein Retest dokumentiert';
    }

    select.disabled = false;
    select.addEventListener('change', renderFinding);
    renderFinding();
  }

  async function loadSignature() {
    const [manifest, signatureFile, keyFile, anchor] = await Promise.all(
      ['manifest.json', 'signature.base64', 'trusted-public.pem', 'report.json'].map(read)
    );
    const der = decode64(decoder.decode(keyFile).replace(/-----(BEGIN|END) PUBLIC KEY-----|\s/g, ''));
    if (await sha256(der) !== keyFingerprint) throw new Error('unexpected demo key');
    const key = await crypto.subtle.importKey('spki', der, 'Ed25519', false, ['verify']);
    const signature = decode64(decoder.decode(signatureFile).trim());
    const prefix = encode.encode(domain);
    async function checkManifest(modified) {
      const message = new Uint8Array(prefix.length + manifest.length);
      message.set(prefix);
      message.set(manifest, prefix.length);
      if (modified) message[message.length - 1] ^= 1;
      return crypto.subtle.verify('Ed25519', key, signature, message);
    }

    // Only parse the original inventory after authenticating its exact bytes.
    if (!await checkManifest(false)) throw new Error('invalid signature');
    const inventory = JSON.parse(decoder.decode(manifest));
    const item = inventory.files.find(entry => entry.path === 'report.json');
    const report = JSON.parse(decoder.decode(anchor));
    if (inventory.signer.public_key_sha256 !== keyFingerprint ||
        !item || item.size !== anchor.length || await sha256(anchor) !== item.sha256 ||
        report.evidence.root_sha256 !== inventory.report.root_sha256 ||
        report.contract_sha256 !== inventory.report.contract_sha256) {
      throw new Error('anchor mismatch');
    }

    controls.disabled = false;
    button.disabled = false;
    controls.addEventListener('change', () => {
      note.textContent = 'Eingabe geändert. Prüfen Sie die gewählte Variante.';
      delete note.dataset.result;
    });
    button.addEventListener('click', async () => {
      controls.disabled = true;
      button.disabled = true;
      try {
        const modified = document.querySelector('input[name="variant"]:checked').value === 'modified';
        const ok = await checkManifest(modified);
        note.dataset.result = ok ? 'valid' : 'invalid';
        note.textContent = ok
          ? 'Gültig. Die Ed25519-Signatur passt zum Originalinventar, der Report-Anker zu seinem SHA-256-Eintrag.'
          : 'Abgelehnt. Die Ed25519-Signatur passt nicht zur veränderten Testkopie.';
      } catch {
        note.textContent = 'Die Signaturprüfung konnte nicht abgeschlossen werden.';
        delete note.dataset.result;
      } finally {
        controls.disabled = false;
        button.disabled = false;
      }
    });
  }

  loadFindings().catch(() => {
    document.getElementById('finding-state').textContent = 'Protokoll nicht verifiziert';
    document.getElementById('finding-note').textContent = 'Für diese Ansicht ist ein ladbares Originalprotokoll mit übereinstimmendem SHA-256-Wert erforderlich.';
    select.disabled = true;
  });
  loadSignature().catch(() => {
    note.textContent = 'Prüfung nicht verfügbar. Erforderlich sind die unveränderten Originaldateien, HTTPS oder localhost und ein Browser mit Ed25519-Unterstützung.';
    button.disabled = true;
    controls.disabled = true;
  });
})();

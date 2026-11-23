// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {open} from 'node:fs/promises';
import {evaluateAccess} from './model.mjs';
import {CASE_LIMIT, POLICY_BYTES, makeBaseline, readPolicy, retestPolicy, sha256} from './retest.mjs';

const usage = 'AuthzLedger RBAC · Node.js 22+\n  node cli.mjs check POLICY.json REQUEST.json\n  node cli.mjs baseline POLICY.json REQUESTS.json\n  node cli.mjs retest BASIS.json ORIGINAL.json CURRENT.json [1,3 | none]\nJSON-Ausgabe auf stdout. Fallnummern beginnen bei 1. Ohne Auswahl werden alle Fälle erneut geprüft.';
async function fileBytes(file) {
  const fd = await open(file,'r');
  try {
    const info = await fd.stat();
    if (!info.isFile() || info.size < 1 || info.size > POLICY_BYTES) throw Error('Zulässig sind reguläre Dateien von 1 Byte bis 2 MiB.');
    const bytes = Buffer.alloc(info.size + 1);
    let read = 0;
    while (read < bytes.length) {
      const part = await fd.read(bytes,read,bytes.length-read,null);
      if (!part.bytesRead) break;
      read += part.bytesRead;
    }
    if (read !== info.size) throw Error('Die Datei wurde beim Lesen verändert.');
    return bytes.subarray(0,read);
  } finally { await fd.close(); }
}
async function jsonFile(file) {
  const bytes = await fileBytes(file);
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
async function main(args) {
  const [command, ...paths] = args;
  if (!command || command === '--help' || command === '-h') return process.stdout.write(usage+'\n');
  let output;
  if (['check','baseline'].includes(command) && paths.length === 2) {
    const bytes = await fileBytes(paths[0]), model = readPolicy(bytes), input = await jsonFile(paths[1]), digest = await sha256(bytes);
    output = command === 'baseline' ? await makeBaseline(digest,input,model)
      : {schema:'authzledger.rbac-check.v1',rights:'© Nasser Aldin Farag (0xFarag). All rights reserved.',signature:'unsigned',
         policy_sha256:digest, request:input, result:evaluateAccess(model,input), warnings:model.warnings};
  } else if (command === 'retest' && [3,4].includes(paths.length)) {
    let selection;
    if (paths.length === 4) {
      if (paths[3] === 'none') selection = [];
      else {
        const parts = paths[3].split(',');
        if (parts.length > CASE_LIMIT || parts.some(p=>!/^([1-9]|[1-9][0-9])$/.test(p))) throw Error('Ungültige Fallnummern.');
        selection = parts.map(p => Number(p)-1);
      }
    }
    output = await retestPolicy(await jsonFile(paths[0]), await fileBytes(paths[1]), await fileBytes(paths[2]), selection);
  } else throw Error(usage);
  process.stdout.write(JSON.stringify(output,null,2)+'\n');
}
main(process.argv.slice(2)).catch(error => {process.stderr.write(error.message+'\n');process.exitCode = 2;});

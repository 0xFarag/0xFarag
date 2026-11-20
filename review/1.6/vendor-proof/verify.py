"""Check unchanged vendor samples and captured native writer output against the installed reader."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from authzledger.federation_offline import project_federation

BASE = Path(__file__).resolve().parent
LOCK = json.loads((BASE / 'provenance.json').read_bytes())
LOOP = ['tcp://127.0.0.1:22', 'tcp://127.0.0.1:80']
SERVICE = ['tcp://192.0.2.10:80']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def project(profile, raw, scope, expected):
    output = project_federation(scope, [(profile, raw)])
    receipt, = output['receipts']
    require(receipt['sha256'] == digest(raw), 'source digest differs')
    dispositions = Counter(r['disposition'] for r in receipt['records'])
    require(dispositions == expected, 'record dispositions differ: ' + str(dispositions))
    require(all(f['evidence_level'] == 'hint' for f in output['graph']['findings']), 'evidence ceiling exceeded')
    return output


def checked(path, checksum):
    raw = path.read_bytes()
    require(digest(raw) == checksum, 'fixture digest mismatch: ' + path.name)
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nmap-dir', type=Path, help='include four independently downloaded upstream boundary checks')
    args = parser.parse_args()
    nmap = LOCK['vendor_nmap']['files']
    bundled = LOCK['bundled_nmap']
    raw = checked(BASE/bundled['original_file'], bundled['sha256'])
    service_ports = (22, 25, 80, 443)
    allowed = [f'tcp://127.0.0.1:{port}' for port in service_ports]
    native = project('nmap', raw, allowed, {'accepted':4})
    expected = [('ssh','open','syn-ack','probed',10), ('smtp','open','syn-ack','probed',10),
                ('http','closed','reset','table',3), ('https','closed','reset','table',3)]
    observations = native['graph']['observations']
    actual = [(o['asserted']['name'],o['asserted']['state'],o['asserted']['reason'],
               o['asserted']['method'],o['asserted']['confidence']) for o in observations]
    require(actual == expected and [o['target'] for o in observations]==allowed, 'Nmap TCP fields differ')
    require(not native['graph']['findings'], 'Nmap inventory produced a finding')
    restricted = project('nmap', raw, allowed[:1], {'accepted':1,'out_of_scope':3})
    require(len(restricted['graph']['observations'])==1, 'exclusion lost')
    rows = [{'file':bundled['original_file'], 'sha256':digest(raw),
             'scope_records':4, 'restricted_scope_omissions':3, 'confirmed':0}]
    for name, spec in sorted(nmap.items()) if args.nmap_dir is not None else []:
        raw = checked(args.nmap_dir / name, spec['sha256'])
        case = spec['expect']
        if case == 'accepted_tcp':
            result = project('nmap', raw, LOOP, {'accepted': 2})
            assert_pairs = [(o['target'], o['asserted']['state'], o['asserted']['name']) for o in result['graph']['observations']]
            require(assert_pairs == [('tcp://127.0.0.1:22','closed','ssh'),('tcp://127.0.0.1:80','open','http')], 'native port assertions differ')
            require(not result['graph']['findings'], 'inventory produced a finding')
        elif case == 'unsupported_udp':
            result = project('nmap', raw, LOOP, {'unsupported_protocol': 8})
            require(not result['graph']['observations'], 'unexpected UDP projection')
        else:
            expected = {'unsupported_identifier','xml_utf8_required'}
            require(case in expected, 'unknown Nmap expectation')
            try:
                project_federation(LOOP, [('nmap', raw)])
            except ValueError as error:
                require(str(error) == case, 'unexpected rejection: ' + str(error))
            else:
                raise ValueError('unsupported export accepted')
        rows.append({'file':name,'sha256':digest(raw),'outcome':case})
    for profile, specs in LOCK['native_writers'].items():
        for name, sha in specs['captured_outputs'].items():
            raw = checked(BASE/'fixtures'/name, sha)
            if name == 'ffuf.json':
                result = project(profile, raw, SERVICE, {'accepted':1, 'out_of_scope':1})
                one, = result['graph']['observations']
                require(one['asserted'] == {'status':200, 'length':2, 'method':'GET'}, 'ffuf fields differ')
            elif name == 'ffuf-context.json':
                require(json.loads(raw)['config']['postdata']=='CONTEXT_CANARY','missing native body field')
                result = project(profile, raw, SERVICE, {'unsupported_request_context':1})
                require(not result['graph']['observations'] and 'CONTEXT_CANARY' not in json.dumps(result), 'raw data surfaced')
            elif name == 'nuclei.jsonl':
                result = project(profile, raw, SERVICE, {'accepted':2})
                observations = result['graph']['observations']
                require([(o['record'], o['asserted']['matched'], o['evidence_level']) for o in observations] == [
                    ('nuclei.jsonl#line:1',True,'hint'),('nuclei.jsonl#line:2',False,None)], 'Nuclei polarity or provenance lost')
                require(len(result['graph']['findings'])==1,'Nuclei finding count differs')
            else:
                raise ValueError('unknown writer fixture')
            rows.append({'file':name,'sha256':digest(raw),'dispositions':result['receipts'][0]['records'],'observations':len(result['graph']['observations']),'confirmed':0})
    print(json.dumps({'schema':'authzledger.native-writer-check/v1','status':'passed','cases':rows},indent=2))

if __name__ == '__main__':
    main()

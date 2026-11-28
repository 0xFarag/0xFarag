"""Native, passive directory graph imports. © Nasser Aldin Farag (0xFarag). All rights reserved."""
from contextlib import closing
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from team import graph_imports, proof_packages
from team.evidence_formats import canonical
from team.proof_engine import DEPENDENCIES, evaluate, import_source, make_scope, verify_semantics

FIXTURES = Path(__file__).parent / 'fixtures'
BH = (FIXTURES / 'bloodhound-groups.json').read_bytes()
NEO = (FIXTURES / 'neo4j-inventory.jsonl').read_bytes()
CONTROLS = dict.fromkeys(DEPENDENCIES, True)


def jsonl(rows):
    return b'\n'.join(map(canonical, rows))


class GraphImports(unittest.TestCase):
    def test_native_graphs_are_minimized_scoped_and_source_local(self):
        sources = [import_source('bloodhound', BH), import_source('neo4j', NEO)]
        identifiers = []
        for src in sources:
            rows = src['observations']
            nodes = {r['inventory']['node']: r['inventory'] for r in rows if r['inventory']['kind'] == 'node'}
            edge = next(r['inventory'] for r in rows if r['inventory']['kind'] == 'edge')
            self.assertEqual(edge['relation'], 'MemberOf')
            self.assertEqual(nodes[edge['from']]['nodeType'], 'User')
            self.assertEqual(nodes[edge['to']]['nodeType'], 'Group')
            self.assertEqual(nodes[edge['from']]['referenceOnly'], src['format'] == 'bloodhound')
            self.assertEqual(len(nodes), 2)
            identifiers.append(set(nodes))
            self.assertNotIn(b'private-', canonical(src))
            self.assertNotIn(b'S-1-5', canonical(src))
        self.assertTrue(identifiers[0].isdisjoint(identifiers[1]))
        scope = make_scope(['corp.example'], 'Review inventory', 4)
        report = evaluate(scope, sources, CONTROLS)
        self.assertEqual([r['status'] for r in report['findings']], ['inconclusive'] * 4 + ['budget_blocked'] * 2)
        self.assertTrue(verify_semantics(report))
        with tempfile.TemporaryDirectory() as tmp, closing(sqlite3.connect(':memory:')) as db, db:
            jwk = proof_packages.key_history(db, Path(tmp), 'team-a')['keys'][0]['jwk']
            archive = proof_packages.sign_package(db, Path(tmp), 'team-a', report)
            self.assertEqual(proof_packages.verify_package(archive, jwk, 'team-a')['source'], sources)
        outside = evaluate(make_scope(['elsewhere.example'], 'Scoped review', 10), sources, CONTROLS)
        self.assertEqual({row['status'] for row in outside['findings']}, {'out_of_scope'})
        self.assertEqual(outside['spent'], 0)

    def test_native_bloodhound_types_count_and_sid_boundary(self):
        original = json.loads(BH)
        for change in [
            lambda g: g['meta'].update(count=2),
            lambda g: g['meta'].update(type='users'),
            lambda g: g['meta'].update(version=3),
            lambda g: g['data'][0].pop('Members'),
            lambda g: g['data'][0]['Properties'].update(domain='192.0.2.1'),
            lambda g: g['data'][0]['Properties'].update(domainsid='S-1-5-21-1-2-3'),
            lambda g: g['data'][0]['Members'][0].update(ObjectIdentifier='S-1-5-21-9-8-7-100'),
            lambda g: g['data'][0]['Members'].append(g['data'][0]['Members'][0]),
        ]:
            value = copy.deepcopy(original)
            change(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                import_source('bloodhound', canonical(value))
        group = original['data'][0]
        member = group['Members'][0]
        member['ObjectType'] = 'Group'
        original['data'].append({'ObjectIdentifier': member['ObjectIdentifier'], 'Properties': group['Properties'], 'Members': []})
        original['meta']['count'] += 1
        src = import_source('bloodhound', canonical(original))
        self.assertFalse(any(r['inventory'].get('referenceOnly') for r in src['observations']))

    def test_neo4j_rejects_dangling_conflicting_or_noninventory_relations(self):
        native = [json.loads(line) for line in NEO.splitlines()]
        for change in [
            lambda rows: rows.pop(0),
            lambda rows: rows.append(rows[0]),
            lambda rows: rows.append(rows[-1]),
            lambda rows: rows[0]['properties'].pop('domain'),
            lambda rows: rows[0]['properties'].update(domain='other.example'),
            lambda rows: rows[-1].update(label='unsupported'),
            lambda rows: rows[-1].update(label='Contains'),
            lambda rows: rows[-1]['start'].update(properties={'domain':'other.example'}),
            lambda rows: rows[-1]['start'].update(labels=['Group']),
            lambda rows: rows[-1].update(start=rows[-1]['end']),
        ]:
            value = copy.deepcopy(native)
            change(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                import_source('neo4j', jsonl(value))
        native[0]['labels'] = ['OU']
        native[-1].update(label='Contains', start={'id':native[0]['id']})
        rows = import_source('neo4j', jsonl(native[::-1]))['observations']
        self.assertEqual(rows[-1]['inventory']['relation'], 'Contains')

    def test_signed_projection_rejects_forged_status_and_dangling_endpoint(self):
        scope = make_scope(['corp.example'], 'Approved inventory', 20)
        src = import_source('neo4j', NEO)
        for extra in ({'status':200}, {'method':'GET'}, {'marker':True}, {'rule':'protected-marker'}):
            fake = copy.deepcopy(src)
            fake['observations'][0].update(extra)
            with self.subTest(change=extra), self.assertRaises(ValueError):
                evaluate(scope, [fake], CONTROLS)
        fake = copy.deepcopy(src)
        edge = fake['observations'][-1]['inventory']
        edge['from'] = '0' * 32
        fake['observations'][-1] = graph_imports._row('neo4j', src['sha256'], 'corp.example', edge)
        with self.assertRaises(ValueError):
            evaluate(scope, [fake], CONTROLS)
        for fmt in ('neo4j','bloodhound'):
            with self.assertRaises(ValueError):
                import_source(fmt, canonical(src))

    def test_file_and_observation_limits_apply_before_projection(self):
        data = [json.loads(NEO.splitlines()[0])]
        with self.assertRaises(ValueError):
            import_source('neo4j', jsonl([{**data[0], 'id':str(i)} for i in range(1001)]))
        with self.assertRaises(ValueError):
            import_source('bloodhound', BH + b' ' * 1048576)


if __name__ == '__main__':
    unittest.main()

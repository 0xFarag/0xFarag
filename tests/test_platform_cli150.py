"""CLI and Studio share persistent assessment IDs and active-plan authorization."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from authzledger.cli import main
from test_detectors150 import service, header_spec, scope_for


class PlatformCliTests(unittest.TestCase):
    def call(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(['assessment', *map(str, args)])

    def test_persistent_cli_plan_run_retest_and_report(self):
        with service() as (origin, state), tempfile.TemporaryDirectory() as directory:
            root = Path(directory); store = root / 'history.sqlite3'
            spec = header_spec(origin)
            (root / 'scope.json').write_text(json.dumps(scope_for(spec)))
            (root / 'spec.json').write_text(json.dumps(spec))
            self.assertEqual(self.call('create', '--store', store, '--title', 'CLI assessment', '--scope', root / 'scope.json', '--out', root / 'assessment.json'), 0)
            aid = json.loads((root / 'assessment.json').read_text())['id']
            self.assertEqual(self.call('check-plan', aid, root / 'spec.json', '--store', store, '--out', root / 'plan.json'), 0)
            plan = json.loads((root / 'plan.json').read_text())
            self.assertEqual(state['requests'], [])
            self.assertEqual(self.call('check-run', aid, plan['artifact_id'], '--store', store, '--approve', '0'*64, '--out', root / 'bad.json'), 2)
            self.assertEqual(state['requests'], [])
            self.assertEqual(self.call('check-run', aid, plan['artifact_id'], '--store', store, '--approve', plan['value']['plan_digest'], '--out', root / 'execution.json'), 1)
            execution = json.loads((root / 'execution.json').read_text())
            state['headers'] = True
            self.assertEqual(self.call('check-retest-plan', aid, execution['artifact_id'], '--store', store, '--out', root / 'retest.json'), 0)
            retest = json.loads((root / 'retest.json').read_text())
            self.assertEqual(self.call('check-retest-run', aid, retest['artifact_id'], '--store', store, '--approve', retest['value']['plan_digest'], '--out', root / 'current.json'), 0)
            self.assertEqual(self.call('freeze', aid, '--store', store, '--out', root / 'snapshot.json'), 0)
            self.assertEqual(self.call('verify', root / 'snapshot.json'), 0)
            self.assertEqual(self.call('report', root / 'snapshot.json', '--formats', 'json', 'html', '--out', root / 'reports'), 0)
            self.assertEqual(len(state['requests']), 4)

    def test_existing_output_prevents_dispatch_and_preserves_bytes(self):
        with service() as (origin, state), tempfile.TemporaryDirectory() as directory:
            from authzledger.workbench import WorkbenchStore, WorkbenchService
            root = Path(directory); store_path = root / 'history.sqlite3'
            store = WorkbenchStore(store_path)
            try:
                workbench = WorkbenchService(store); spec = header_spec(origin)
                assessment = workbench.create('Existing output test', scope_for(spec))
                plan = workbench.check_plan(assessment['id'], spec)
            finally:
                store.close()
            target = root / 'existing.json'; target.write_text('retain these bytes')
            self.assertEqual(self.call('check-run', assessment['id'], plan['artifact_id'], '--store', store_path,
                '--approve', plan['value']['plan_digest'], '--out', target), 2)
            self.assertEqual(target.read_text(), 'retain these bytes')
            self.assertEqual(state['requests'], [])


if __name__ == '__main__':
    unittest.main()

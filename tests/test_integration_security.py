"""Independent adversarial tests for cross-module evidence claims and secrets."""
import contextlib
import copy
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from authzledger.experiments import compile_experiment, execute_experiment, verify_execution, compare_executions, plan_experiment_retest, _finding
from authzledger.evidence import seal_report
from authzledger.intelligence import build_graph
from authzledger.oracles import seal
from authzledger.assessment_reports import freeze_assessment
from test_experiments import fixture_spec, fixture_service


def rebind_report_metadata(execution):
    """Attacker recomputes every unkeyed derived commitment after changing tool."""
    execution['report'] = seal_report(execution['report'])
    execution['graph'] = build_graph(execution['contract'], execution['report'])
    for index, observation in enumerate(execution['observations']):
        observation['report_root'] = execution['report']['evidence']['root_sha256']
        execution['observations'][index] = seal('observation', observation, 'observation_digest')
        execution['findings'][index] = _finding(execution['plan'], execution['plan']['variants'][index], execution['observations'][index])
    return seal('experiment-execution', execution, 'execution_digest')


@contextlib.contextmanager
def reflected_credential_service():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            actor = self.headers.get('Authorization')
            if self.path == '/me': status, body = 200, {'principal':'peer','tenant':'B'}
            elif self.path == '/invoice/A' and actor == 'Bearer owner-private-value': status, body = 200, {'marker':'synthetic-A'}
            elif self.path == '/known-denial': status, body = 403, {'error':'denied'}
            else: status, body = 403, {'marker':actor}
            raw = json.dumps(body).encode()
            self.send_response(status); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
    with patch.dict('os.environ',{'CONTRAST_OWNER':'Bearer owner-private-value','CONTRAST_PEER':'Bearer peer-private-value'}):
        try:yield 'http://127.0.0.1:'+str(server.server_port)
        finally:server.shutdown();server.server_close();thread.join(2)


class IntegrationSecurityTests(unittest.TestCase):
    def test_selected_oracle_value_cannot_persist_a_reflected_runtime_credential(self):
        with reflected_credential_service() as target:
            execution=execute_experiment(compile_experiment(fixture_spec(target)))
        serialized=json.dumps(execution)
        self.assertFalse('Bearer peer-private-value' in serialized,'runtime credential retained in execution')
        self.assertFalse('Bearer owner-private-value' in serialized,'runtime credential retained in execution')
        self.assertEqual(execution['observations'][0]['interpretation'],'inconclusive')
        self.assertEqual(verify_execution(execution),[])
        snapshot=freeze_assessment([execution],{})
        self.assertNotIn('Bearer peer-private-value',json.dumps(snapshot))

    def test_unknown_tool_version_is_not_a_verified_execution_profile(self):
        with fixture_service() as (target,_):
            execution=execute_experiment(compile_experiment(fixture_spec(target)))
        execution['report']['tool']['version']='9999.0.0'
        execution=rebind_report_metadata(execution)
        self.assertTrue(verify_execution(execution))
        with self.assertRaises(ValueError):freeze_assessment([execution],{})

    def test_foreign_tool_name_is_not_authzledger_semantics(self):
        with fixture_service() as (target,_):
            execution=execute_experiment(compile_experiment(fixture_spec(target)))
        execution['report']['tool']['name']='foreign-engine'
        execution=rebind_report_metadata(execution)
        self.assertTrue(verify_execution(execution))

    def test_self_consistent_empty_budget_cannot_describe_executed_report(self):
        with fixture_service() as (target,_):
            execution=execute_experiment(compile_experiment(fixture_spec(target)))
        ledger=execution['budget_ledger']
        ledger['requests']=[];ledger['dispatched_total']=0
        ledger['by_kind']={kind:0 for kind in ledger['by_kind']}
        ledger['remaining']=ledger['approved_total']
        execution=seal('experiment-execution',execution,'execution_digest')
        self.assertTrue(verify_execution(execution))

    def test_cross_origin_finding_id_collision_never_hides_confirmed_finding(self):
        with fixture_service() as (target,_):
            first=execute_experiment(compile_experiment(fixture_spec(target)))
        with fixture_service() as (target,state):
            state['mode']='fixed'
            second=execute_experiment(compile_experiment(fixture_spec(target)))
        try:
            snapshot=freeze_assessment([first,second],{})
        except ValueError:
            return  # Explicit collision rejection is an acceptable fail-closed result.
        self.assertEqual(len(snapshot['findings']),2)
        self.assertEqual(snapshot['summary']['confirmed'],1)

    def test_changed_rule_cannot_overwrite_a_prior_confirmed_finding_as_a_fix(self):
        with fixture_service() as (target,_):
            first=execute_experiment(compile_experiment(fixture_spec(target)))
            other=fixture_spec(target)
            other['rule']['value']='weakened-marker'
            other['contract']['cases'][1]['expect']['json']['/marker']='weakened-marker'
            second=execute_experiment(compile_experiment(other))
        try:
            snapshot=freeze_assessment([first,second],{})
        except ValueError:
            return
        self.assertEqual(len(snapshot['findings']),2)
        self.assertEqual(snapshot['summary']['confirmed'],1)

    def test_retained_projection_cannot_contradict_original_absence_check(self):
        with fixture_service() as (target,state):
            state['mode']='fixed'
            execution=execute_experiment(compile_experiment(fixture_spec(target)))
        self.assertEqual(execution['report']['summary']['fail'],0)
        observation=execution['observations'][0]
        observation['oracle']['input']={'present':True,'value':'synthetic-A'}
        observation['oracle']['decision']={'interpretation':'violation','reason':'predicate_violated'}
        observation['interpretation']='violation'
        execution['observations'][0]=seal('observation',observation,'observation_digest')
        execution['findings'][0]=_finding(execution['plan'],execution['plan']['variants'][0],execution['observations'][0])
        execution=seal('experiment-execution',execution,'execution_digest')
        self.assertTrue(verify_execution(execution))

    def test_attested_predicate_cannot_contradict_original_absence_check(self):
        with fixture_service() as (target,state):
            state['mode']='fixed'
            execution=execute_experiment(compile_experiment(fixture_spec(target,'attested')))
        observation=execution['observations'][0]
        observation['oracle']['decision']={'interpretation':'violation','reason':'predicate_violated'}
        observation['interpretation']='violation'
        execution['observations'][0]=seal('observation',observation,'observation_digest')
        execution['findings'][0]=_finding(execution['plan'],execution['plan']['variants'][0],execution['observations'][0])
        execution=seal('experiment-execution',execution,'execution_digest')
        self.assertTrue(verify_execution(execution))

    def test_invalid_json_report_cannot_be_recast_as_a_valid_json_oracle_capture(self):
        with fixture_service() as (target,state):
            state['mode']='duplicate'
            execution=execute_experiment(compile_experiment(fixture_spec(target)))
        observation=execution['observations'][0]
        observation['oracle']['input']={'present':True,'value':'synthetic-A'}
        observation['oracle']['decision']={'interpretation':'violation','reason':'predicate_violated'}
        observation['interpretation']='violation'
        execution['observations'][0]=seal('observation',observation,'observation_digest')
        execution['findings'][0]=_finding(execution['plan'],execution['plan']['variants'][0],execution['observations'][0])
        execution=seal('experiment-execution',execution,'execution_digest')
        self.assertTrue(verify_execution(execution))

    def test_unknown_baseline_to_confirmed_violation_is_not_claimed_as_regression(self):
        with fixture_service() as (target,state):
            state['mode']='invalid_controls'
            baseline=execute_experiment(compile_experiment(fixture_spec(target)))
            state['mode']='vulnerable'
            current=execute_experiment(plan_experiment_retest(baseline,['cross-tenant']))
            comparison=compare_executions(baseline,current)
        self.assertEqual(current['findings'][0]['status'],'confirmed')
        self.assertEqual(baseline['findings'][0]['interpretation'],'inconclusive')
        self.assertEqual(comparison['transitions'][0]['status'],'inconclusive')

    def test_workflow_binding_cannot_export_reflected_runtime_credential(self):
        from test_workflows import fixture as workflow_fixture, spec as workflow_spec
        from authzledger.workflows import compile_workflow,execute_workflow,verify_workflow
        with workflow_fixture() as (target,state), patch.dict('os.environ',{'WORKFLOW_SECRET_TEST':'Bearer reflected-workflow-private'}):
            source=workflow_spec(target)
            source['contract']['identities']['operator']['headers']={'Authorization':{'env':'WORKFLOW_SECRET_TEST'}}
            state['binding_response']={'id':'Bearer reflected-workflow-private'}
            trace=execute_workflow(compile_workflow(source))
        self.assertFalse('reflected-workflow-private' in json.dumps(trace),'credential reflected into materialized workflow request')
        self.assertEqual(trace['variants'][0]['interpretation'],'inconclusive')
        self.assertEqual(verify_workflow(trace),[])

    def test_encoded_fixture_reflection_is_withheld_from_history_and_assessment(self):
        import tempfile
        from pathlib import Path
        from urllib.parse import quote
        from test_workflows import fixture as workflow_fixture
        from test_workflow_assurance import assurance_spec
        from authzledger.history import HistoryStore
        from authzledger.workflow_assurance import compile_workflow_assurance,run_workflow_assurance,verify_workflow_assurance
        from authzledger.assessment_reports import render_assessment_json,render_assessment_html
        secret='Bearer history-reflection-private'
        for reflected in (secret,quote(quote(secret,safe=''),safe='')):
            with self.subTest(reflected=reflected), tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'history.sqlite3'
                history=HistoryStore(path)
                try:
                    with workflow_fixture() as (target,state), patch.dict('os.environ',{'WORKFLOW_HISTORY_SECRET':secret}):
                        source=assurance_spec(target)
                        source['workflow']['contract']['identities']['operator']['headers']={'Authorization':{'env':'WORKFLOW_HISTORY_SECRET'}}
                        state['binding_response']={'id':reflected}
                        result=run_workflow_assurance(compile_workflow_assurance(source),history=history)
                    self.assertEqual(result['completed_cycles'],1)
                    self.assertEqual(result['stop_reason'],'cleanup_pending')
                    self.assertEqual(state['requests'],[('GET','/control'),('POST','/objects')])
                    self.assertEqual(result['budget_ledger']['dispatched_total'],2)
                    self.assertEqual(verify_workflow_assurance(result),[])
                    rows=history.workflow_snapshot()['records']
                    self.assertEqual(len(rows),1)
                    snapshot=freeze_assessment([],{},assurances=[result])
                    surfaces=[json.dumps(result),json.dumps(rows),render_assessment_json(snapshot),render_assessment_html(snapshot)]
                    for surface in surfaces:
                        self.assertNotIn('history-reflection-private',surface)
                        self.assertNotIn(reflected,surface)
                finally:
                    history.close()
                self.assertNotIn(b'history-reflection-private',path.read_bytes())
                self.assertNotIn(reflected.encode(),path.read_bytes())

    def test_short_credential_substrings_cannot_enter_dynamic_workflow_bindings(self):
        from urllib.parse import quote
        from test_workflows import fixture as workflow_fixture, spec as workflow_spec
        from authzledger.workflows import compile_workflow,execute_workflow,verify_workflow
        for secret in ('abc123','ab+123'):
            for reflected in ('prefix-'+secret+'-suffix',quote(quote('prefix-'+secret+'-suffix',safe=''),safe='')):
                with self.subTest(secret=secret,reflected=reflected),workflow_fixture() as (target,state):
                    source=workflow_spec(target)
                    source['contract']['identities']['operator']['headers']={'X-Api-Key':{'env':'WORKFLOW_SHORT_SECRET'}}
                    state['binding_response']={'id':reflected}
                    registry=set()
                    with patch.dict('os.environ',{'WORKFLOW_SHORT_SECRET':secret}):
                        trace=execute_workflow(compile_workflow(source),fixture_registry=registry)
                    self.assertEqual(registry,set())
                    self.assertEqual(state['requests'],[('GET','/control'),('POST','/objects')])
                    self.assertEqual(trace['variants'][0]['interpretation'],'inconclusive')
                    self.assertEqual(verify_workflow(trace),[])
                    self.assertNotIn(secret,json.dumps(trace))
                    self.assertNotIn(reflected,json.dumps(trace))

    def test_incomplete_capture_cannot_confirm_even_when_all_hashes_are_rebuilt(self):
        with fixture_service() as (target,_):
            execution=execute_experiment(compile_experiment(fixture_spec(target)))
        observation=execution['observations'][0]
        observation['body_complete']=False
        execution['observations'][0]=seal('observation',observation,'observation_digest')
        execution['findings'][0]=_finding(execution['plan'],execution['plan']['variants'][0],execution['observations'][0])
        execution=seal('experiment-execution',execution,'execution_digest')
        self.assertTrue(verify_execution(execution))


if __name__=='__main__':unittest.main()

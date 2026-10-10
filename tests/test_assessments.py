import copy
import unittest
from authzledger.assessments import AssessmentStore,RevisionConflict,plan_impacted_retest,build_evidence_graph,verify_evidence_graph,inspect_finding
from test_experiments import fixture_spec

class AssessmentTests(unittest.TestCase):
    def test_revision_compare_swap_and_copy_isolation(self):
        store=AssessmentStore();first=store.create(fixture_spec());second=store.revise(first['id'],fixture_spec(),expected_revision=1)
        self.assertEqual(second['revision'],2)
        with self.assertRaises(RevisionConflict):store.revise(first['id'],fixture_spec(),expected_revision=1)
        second['spec']['title']='changed';self.assertNotEqual(store.get(first['id'])['spec']['title'],'changed')
    def test_unknown_change_requires_full_scope(self):
        change={'kind':'source','id':'unknown','before_digest':'0'*64,'after_digest':'1'*64}
        result=plan_impacted_retest(fixture_spec()['contract'],[change]);self.assertEqual(result['request_upper_bound'],4)
        self.assertEqual(result['unknown_dependencies'],['source:unknown']);self.assertEqual(result['not_retested_ids'],[])
    def test_known_case_change_closes_controls_and_dependents(self):
        change={'kind':'case','id':'actor','before_digest':'0'*64,'after_digest':'1'*64}
        result=plan_impacted_retest(fixture_spec()['contract'],[change]);self.assertEqual(result['request_upper_bound'],4)
        self.assertEqual(result['reasons']['owner'][0]['reason_code'],'required_control')
    def test_same_change_same_reasoned_plan(self):
        change={'kind':'rule','id':'tenant','before_digest':'0'*64,'after_digest':'1'*64};source=fixture_spec()['contract']
        self.assertEqual(plan_impacted_retest(source,[change],{'rule:tenant':['target']}),plan_impacted_retest(source,[copy.deepcopy(change)],{'rule:tenant':['target']}))
    def test_no_change_has_no_requests(self):
        change={'kind':'case','id':'actor','before_digest':'0'*64,'after_digest':'0'*64}
        self.assertEqual(plan_impacted_retest(fixture_spec()['contract'],[change])['request_upper_bound'],0)

    def test_inspector_graph_reconstructs_exact_provenance(self):
        from test_experiments import fixture_service
        from authzledger.experiments import compile_experiment,execute_experiment
        with fixture_service() as (url,state):execution=execute_experiment(compile_experiment(fixture_spec(url)))
        graph=build_evidence_graph(execution);self.assertEqual(verify_evidence_graph(graph,execution),[])
        view=inspect_finding(execution,execution['findings'][0]['id']);self.assertEqual(len(view['controls']),3)
        graph['edges'].append({'source':'made-up','target':'other','relation':'requires'})
        self.assertTrue(verify_evidence_graph(graph,execution))

    def test_impact_catalog_matches_full_run_for_each_declared_change_kind(self):
        from test_experiments import fixture_service
        from authzledger.experiments import compile_experiment,execute_experiment
        from authzledger import engine
        with fixture_service() as (url,state):
            spec=fixture_spec(url)
            outside=copy.deepcopy(spec['contract']['cases'][1]);outside['id']='unaffected';spec['contract']['cases'].append(outside)
            full=execute_experiment(compile_experiment(spec))
            expected={r['id']:(r['outcome'],r['status'],r['checks']) for r in full['report']['results'] if r['id']!='unaffected'}
            for kind in ('rule','case','identity_binding','fixture','policy','oracle','normalizer','source'):
                with self.subTest(kind=kind):
                    identifier='target' if kind=='case' else 'declared'
                    change={'kind':kind,'id':identifier,'before_digest':'0'*64,'after_digest':'1'*64}
                    plan=plan_impacted_retest(spec['contract'],[change],{kind+':'+identifier:['target']})
                    partial=engine.run(plan['contract'])
                    actual={r['id']:(r['outcome'],r['status'],r['checks']) for r in partial['results']}
                    self.assertEqual(actual,expected)
                    self.assertEqual(plan['not_retested_ids'],['unaffected'])
                    self.assertEqual(plan['unknown_dependencies'],[])
                    self.assertEqual(plan['reasons']['target'][0]['reason_code'],'changed_'+kind)

    def test_repeated_import_keeps_one_finding_with_two_evidence_versions(self):
        import json
        from test_experiments import fixture_service
        from authzledger.imports import parse_import
        from authzledger.experiments import compile_imported_experiment,execute_experiment
        from authzledger.assessment_reports import freeze_assessment
        with fixture_service() as (url,state):
            raw=json.dumps({'log':{'version':'1.2','entries':[{'request':{'method':'GET','url':url+'/invoice/A','headers':[{'name':'Authorization','value':'Bearer imported-secret'}]},'response':{'status':403}}]}}).encode()
            first=parse_import(raw,'har-1.2');second=parse_import(raw,'har-1.2')
            self.assertEqual(first,second)
            spec=fixture_spec(url)
            bindings={'id':'imported','title':'Repeated imported source','target':url,'identities':spec['contract']['identities'],'actor_identity':'peer','owner_identity':'owner','identity_probe':{'path':'/me','expect':spec['contract']['cases'][0]['expect']},'negative_probe':{'path':'/known-denial','expect':spec['contract']['cases'][2]['expect']},'rule':spec['rule'],'capture_mode':'safe_values'}
            plan1=compile_imported_experiment(first['entries'][0],bindings);plan2=compile_imported_experiment(second['entries'][0],bindings)
            self.assertEqual(plan1,plan2)
            executions=[execute_experiment(plan1),execute_experiment(plan2)]
            snapshot=freeze_assessment(executions,{})
            self.assertEqual(len(snapshot['findings']),1)
            self.assertEqual(len(snapshot['executions']),2)
            self.assertEqual(executions[0]['findings'][0]['id'],executions[1]['findings'][0]['id'])
            self.assertNotIn('Bearer imported-secret',json.dumps(snapshot))

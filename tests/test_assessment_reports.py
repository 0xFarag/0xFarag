"""Assessment export parity, exact signed bytes and retained source semantics."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from authzledger.assessment_reports import (freeze_assessment, verify_assessment, render_assessment_json,
    render_assessment_html, render_assessment_pdf, export_assessment, create_assessment_bundle,
    assessment_attachments, validate_cvss_vector, _canonical, _DOMAIN)
from authzledger.experiments import compile_experiment, execute_experiment, plan_experiment_retest, compare_executions
from authzledger.signing import generate_keypair, create_bundle, verify_bundle, _signature
from test_experiments import fixture_spec, fixture_service

PDF_AVAILABLE = importlib.util.find_spec('reportlab') is not None
VECTOR = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'


def rehash(snapshot):
    snapshot.pop('snapshot_digest', None)
    snapshot['snapshot_digest'] = hashlib.sha256(_DOMAIN + _canonical(snapshot)).hexdigest()
    return snapshot


class AssessmentReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with fixture_service() as (url, state):
            cls.execution = execute_experiment(compile_experiment(fixture_spec(url)))
            state['mode'] = 'fixed'
            cls.retest = execute_experiment(plan_experiment_retest(cls.execution, ['cross-tenant']))
            cls.comparison = compare_executions(cls.execution, cls.retest)
        cls.snapshot = freeze_assessment([cls.execution], {'title':'Tenant isolation / Zürich αβγ', 'reviewer':'Security reviewer'})

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def test_snapshot_is_detached_and_original_roots_unchanged(self):
        execution = copy.deepcopy(self.execution); original = copy.deepcopy(execution)
        snapshot = freeze_assessment([execution], {'title':'Assessment'})
        self.assertEqual(execution, original)
        snapshot['executions'][0]['report']['tool']['version'] = 'bad'
        self.assertEqual(execution, original)
        self.assertTrue(verify_assessment(snapshot))

    def test_snapshot_reconstruction_and_nonoverridable_statuses(self):
        self.assertEqual(verify_assessment(self.snapshot), [])
        for mutate in [lambda s:s['summary'].update(confirmed=0), lambda s:s['findings'][0]['record'].update(status='rejected'),
                       lambda s:s.update(manifest_digest='a'*64), lambda s:s['findings'][0]['source'].update(report_root='0'*64)]:
            altered = copy.deepcopy(self.snapshot); mutate(altered); rehash(altered)
            self.assertTrue(verify_assessment(altered))

    def test_invalid_execution_or_foreign_observation_never_freezes(self):
        bad = copy.deepcopy(self.execution); bad['observations'][0]['case_id'] = 'absent'
        with self.assertRaises(ValueError): freeze_assessment([bad], {})
        bad = copy.deepcopy(self.execution); bad['findings'][0]['evidence_refs'] = ['0'*64]
        with self.assertRaises(ValueError): freeze_assessment([bad], {})

    def test_annotated_standards_require_same_finding_evidence(self):
        f = self.execution['findings'][0]
        mapping = {'standard':'ASVS', 'version':'5.0.0','id':'8.2.2','relation':'partially_covers',
                   'rationale':'One selected object and identity were evaluated.', 'evidence_refs':f['evidence_refs']}
        metadata = {'finding_annotations':{f['id']:{'cvss_vector':VECTOR,'standard_refs':[mapping], 'business_risk':'Reviewer context remains limited.'}}}
        snapshot = freeze_assessment([self.execution], metadata)
        self.assertEqual(snapshot['findings'][0]['severity']['score'], None)
        self.assertEqual(snapshot['findings'][0]['severity']['status'], 'not_scored')
        self.assertIn('not certification', render_assessment_html(snapshot))
        mapping['evidence_refs'] = ['1'*64]
        with self.assertRaises(ValueError): freeze_assessment([self.execution], metadata)

    def test_unreviewed_or_unknown_standard_and_score_are_rejected(self):
        fid = self.execution['findings'][0]['id']
        for annotation in ({'status':'confirmed'}, {'score':9.8}, {'standard_refs':[{'standard':'ASVS','version':'4.0.3','id':'4.1.1','relation':'supports','rationale':'Wrong catalog','evidence_refs':['0'*64]}]}):
            with self.assertRaises(ValueError): freeze_assessment([self.execution], {'finding_annotations':{fid:annotation}})

    def test_three_partial_asvs_mappings_never_claim_global_compliance(self):
        finding = self.execution['findings'][0]
        refs = [{'standard':'ASVS','version':'5.0.0','id':rid,'relation':'partially_covers',
                 'rationale':'Only the named request, identity and object were evaluated; remaining requirement scope is untested.',
                 'evidence_refs':finding['evidence_refs']} for rid in ('8.2.1','8.2.2','8.4.1')]
        snapshot = freeze_assessment([self.execution], {'finding_annotations':{finding['id']:{'standard_refs':refs}}})
        self.assertEqual(len(snapshot['findings'][0]['standard_refs']),3)
        for rendered in (render_assessment_json(snapshot),render_assessment_html(snapshot)):
            for rid in ('8.2.1','8.2.2','8.4.1'): self.assertIn(rid,rendered)
            self.assertIn('partially_covers',rendered)
            self.assertIn('not certification',rendered)
            self.assertIn('remaining requirement scope is untested',rendered)

    def test_manifest_self_reference_and_circular_snapshot_are_rejected(self):
        altered = copy.deepcopy(self.snapshot)
        altered['manifest_digest'] = altered['snapshot_digest']
        rehash(altered)
        self.assertTrue(verify_assessment(altered))
        circular = copy.deepcopy(self.snapshot)
        circular['self'] = circular
        self.assertTrue(verify_assessment(circular))

    def test_cvss_full_grammar_and_fixed_order(self):
        self.assertEqual(validate_cvss_vector(VECTOR)['vector'],VECTOR)
        full = VECTOR+'/E:A/CR:H/IR:M/AR:L/MAV:N/MAC:L/MAT:N/MPR:L/MUI:N/MVC:H/MVI:N/MVA:N/MSC:N/MSI:S/MSA:S/S:P/AU:Y/R:A/V:D/RE:L/U:Red'
        self.assertEqual(validate_cvss_vector(full)['status'],'not_scored')
        for bad in (VECTOR.replace('/AT:N',''), VECTOR+'/E:A/E:X',VECTOR.replace('AV:N/AC:L','AC:L/AV:N'), VECTOR+'/MSC:S',VECTOR+'/U:RED',VECTOR.replace('4.0','3.1'),VECTOR+'/XX:N'):
            with self.subTest(vector=bad), self.assertRaises(ValueError): validate_cvss_vector(bad)

    def test_html_escapes_every_user_string_and_has_no_external_assets(self):
        malicious = '<script src="https://evil.invalid/a"></script><img src="file:///etc/passwd">'
        snapshot = freeze_assessment([self.execution], {'title':malicious,'executive_summary':malicious})
        with patch('socket.getaddrinfo', side_effect=AssertionError('network access')):
            html = render_assessment_html(snapshot)
        self.assertNotIn('<script',html);self.assertNotIn('<img',html);self.assertIn('&lt;script',html)
        self.assertIn("default-src 'none'",html)

    def test_snapshot_and_renderers_share_status_id_and_evidence(self):
        snapshot = freeze_assessment([self.execution,self.retest], {}, [self.comparison])
        html = render_assessment_html(snapshot); raw = render_assessment_json(snapshot)
        self.assertEqual(json.loads(raw),snapshot)
        row = snapshot['findings'][0]
        for value in [row['id'],row['record']['status'],*row['record']['evidence_refs'],row['source']['report_root']]:
            self.assertIn(value,html);self.assertIn(value,raw)
        self.assertIn('fix_verified',html)
        self.assertEqual(row['status'], 'retest_verified')
        self.assertEqual(snapshot['summary']['retest_verified'], 1)
        self.assertEqual(snapshot['executions'][0]['report'],self.execution['report'])

    def test_failed_controls_cannot_erase_open_finding_and_argument_order_is_not_time(self):
        with fixture_service() as (url, state):
            baseline = execute_experiment(compile_experiment(fixture_spec(url)))
            state['mode'] = 'invalid_controls'
            current = execute_experiment(plan_experiment_retest(baseline, ['cross-tenant']))
            comparison = compare_executions(baseline, current)
        first = freeze_assessment([baseline, current], {})
        reversed_input = freeze_assessment([current, baseline], {})
        self.assertEqual(first['findings'], reversed_input['findings'])
        self.assertEqual(first['findings'][0]['status'], 'confirmed')
        compared = freeze_assessment([current, baseline], {}, [comparison])
        self.assertEqual(compared['findings'][0]['status'], 'retest_pending')
        self.assertEqual(compared['findings'][0]['record']['interpretation'], 'inconclusive')
        self.assertEqual(compared['summary']['retest_pending'], 1)

    def test_explicit_comparison_selects_current_independent_of_argument_order(self):
        forward = freeze_assessment([self.execution,self.retest], {}, [self.comparison])
        reverse = freeze_assessment([self.retest,self.execution], {}, [self.comparison])
        self.assertEqual(forward['findings'],reverse['findings'])
        self.assertEqual(reverse['findings'][0]['status'],'retest_verified')

    def test_retest_omissions_keep_not_retested(self):
        self.assertIn('not_retested',render_assessment_html(self.snapshot))
        self.assertEqual(self.snapshot['findings'][0]['retests'],[])

    def test_forged_rehashed_fix_comparison_and_missing_execution_rejected(self):
        from authzledger.oracles import seal
        forged = copy.deepcopy(self.comparison)
        forged['transitions'][0]['status'] = 'violation_persists'
        forged = seal('experiment-comparison', forged, 'comparison_digest')
        with self.assertRaisesRegex(ValueError, 'comparison does not match'):
            freeze_assessment([self.execution, self.retest], {}, [forged])
        with self.assertRaisesRegex(ValueError, 'comparison does not match'):
            freeze_assessment([self.execution], {}, [self.comparison])

    def test_invalid_empty_collection_types_rejected(self):
        for keyword in ('comparisons', 'workflows', 'reductions'):
            with self.subTest(keyword=keyword), self.assertRaises(ValueError):
                freeze_assessment([self.execution], {}, **{keyword:{}})

    def test_freeze_and_export_are_offline_and_no_overwrite(self):
        with patch('socket.getaddrinfo',side_effect=AssertionError('network')):
            snapshot=freeze_assessment([self.execution],{})
            files=export_assessment(snapshot,self.root/'report',('json','html'))
        self.assertEqual(set(files),{'assessment.json','assessment.html'})
        with self.assertRaises(ValueError):export_assessment(snapshot,self.root/'report',('json',))
        with self.assertRaises(ValueError):export_assessment(snapshot,self.root/'invalid',('svg',))
        self.assertFalse((self.root/'invalid').exists())

    @unittest.skipUnless(PDF_AVAILABLE,'reports extra not installed')
    def test_pdf_is_deterministic_and_unicode_is_preserved(self):
        with patch('socket.getaddrinfo',side_effect=AssertionError('network')):
            pdf = render_assessment_pdf(self.snapshot)
            self.assertEqual(pdf,render_assessment_pdf(self.snapshot))
        self.assertTrue(pdf.startswith(b'%PDF-'))
        try: from pypdf import PdfReader
        except ImportError: return
        import io
        text='\n'.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages)
        self.assertIn('Zürich αβγ',text)
        for row in self.snapshot['findings']:
            for value in [row['id'],row['record']['status'],*row['record']['evidence_refs']]: self.assertIn(value,text)

    @unittest.skipUnless(PDF_AVAILABLE,'reports extra not installed')
    def test_missing_unicode_glyph_is_explicit_export_failure(self):
        snapshot=freeze_assessment([self.execution],{'title':'Unsupported \U0001f6d6'})
        with self.assertRaisesRegex(ValueError,'font does not cover'):render_assessment_pdf(snapshot)

    def test_bundle_binds_originals_and_semantic_snapshot(self):
        private,public=self.root/'private.pem',self.root/'trusted.pem';generate_keypair(private,public)
        create_assessment_bundle(self.snapshot,self.root/'proof',private,('json','html'))
        self.assertEqual(verify_bundle(self.root/'proof',public),[])
        script=Path(__file__).resolve().parents[1]/'tools'/'verify_bundle.py'
        result=subprocess.run([sys.executable,'-I',str(script),str(self.root/'proof'),'--public-key',str(public)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('not established',result.stdout)
        wrong=copy.deepcopy(self.snapshot);wrong['findings'][0]['record']['status']='rejected';rehash(wrong)
        with self.assertRaises(ValueError):create_bundle(self.execution['report'],self.root/'bad',private,{'assessment.json':_canonical(wrong)+b'\n'})

    def test_visual_attachment_requires_snapshot(self):
        private,public=self.root/'private.pem',self.root/'trusted.pem';generate_keypair(private,public)
        with self.assertRaisesRegex(ValueError,'require assessment.json'):
            create_bundle(self.execution['report'],self.root/'bad',private,{'assessment.html':b'<html>False finding</html>'})

    @unittest.skipUnless(PDF_AVAILABLE,'reports extra not installed')
    def test_resigned_inconsistent_pdf_is_semantically_rejected(self):
        private,public=self.root/'private.pem',self.root/'trusted.pem';generate_keypair(private,public)
        proof=self.root/'proof';create_assessment_bundle(self.snapshot,proof,private)
        pdf=proof/'attachments'/'assessment.pdf';pdf.write_bytes(pdf.read_bytes()+b'\n% false added report statement\n')
        self.assertTrue(verify_bundle(proof,public))
        script=Path(__file__).resolve().parents[1]/'tools'/'verify_bundle.py'
        corrupted=subprocess.run([sys.executable,'-I',str(script),str(proof),'--public-key',str(public)],capture_output=True,text=True)
        self.assertNotEqual(corrupted.returncode,0)
        # A holder of the key can sign dishonest bytes. Main verification must
        # still reject exact-render mismatch; standalone only verifies integrity.
        manifest=json.loads((proof/'manifest.json').read_text())
        for entry in manifest['files']:
            if entry['path']=='attachments/assessment.pdf':
                entry['size']=pdf.stat().st_size;entry['sha256']=hashlib.sha256(pdf.read_bytes()).hexdigest()
        from authzledger.signing import _canonical as bundle_canonical
        raw=bundle_canonical(manifest);(proof/'manifest.json').write_bytes(raw)
        (proof/'signature.base64').write_bytes(base64.b64encode(_signature(raw,private.read_bytes()))+b'\n')
        errors=verify_bundle(proof,public)
        self.assertTrue(any('assessment.pdf does not match' in e for e in errors),errors)
        result=subprocess.run([sys.executable,'-I',str(script),str(proof),'--public-key',str(public)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_malformed_snapshots_return_errors(self):
        for value in (None,[],{}, {'executions':None,'metadata':{},'comparisons':[]}):
            self.assertTrue(verify_assessment(value))

    def test_workflow_only_snapshot_and_proof_preserve_materialized_reports(self):
        from test_workflows import fixture, spec
        from authzledger.workflows import compile_workflow, execute_workflow
        with fixture() as (origin, state):
            trace = execute_workflow(compile_workflow(spec(origin)))
        snapshot = freeze_assessment([], {'title':'Workflow proof'}, workflows=[trace])
        self.assertEqual(verify_assessment(snapshot), [])
        self.assertEqual(snapshot['workflow_findings'][0]['status'], 'confirmed')
        rendered = render_assessment_html(snapshot)
        self.assertIn('evaluation_attested', rendered)
        self.assertIn(trace['workflow_digest'], rendered)
        self.assertIn(trace['variants'][0]['steps'][0]['report']['evidence']['root_sha256'], rendered)
        private, public = self.root/'private.pem', self.root/'trusted.pem'
        generate_keypair(private, public)
        create_assessment_bundle(snapshot, self.root/'workflow-proof', private, ('json','html'))
        self.assertEqual(verify_bundle(self.root/'workflow-proof', public), [])

    def test_reduction_trace_is_verified_and_bound_to_original(self):
        from authzledger.minimize import plan_reduction, execute_reduction, removable_units
        with fixture_service() as (url, state):
            spec = fixture_spec(url)
            spec['contract']['cases'][-1]['headers'] = {'Accept':'application/json'}
            original = execute_experiment(compile_experiment(spec))
            trace = execute_reduction(plan_reduction(original, removable_units(original), max_requests=12))
        snapshot = freeze_assessment([original], {}, reductions=[trace])
        self.assertEqual(verify_assessment(snapshot), [])
        self.assertIn(trace['reduction_digest'], render_assessment_html(snapshot))
        with self.assertRaisesRegex(ValueError, 'original is not'):
            freeze_assessment([self.execution], {}, reductions=[trace])
        changed = copy.deepcopy(trace); changed['one_minimal'] = 'yes'
        with self.assertRaises(ValueError): freeze_assessment([original], {}, reductions=[changed])

    def test_two_cycle_assurance_snapshot_and_signed_proof_bind_history_and_budget(self):
        from authzledger.history import HistoryStore
        from authzledger.workflow_assurance import compile_workflow_assurance, run_workflow_assurance
        from test_workflows import fixture, spec
        with fixture() as (origin, state), HistoryStore(self.root/'history.sqlite3') as history:
            state['vulnerable'] = False
            plan = compile_workflow_assurance({'schema_version':1,'kind':'workflow-assurance-spec',
                'workflow':spec(origin),'max_cycles':2,'interval_seconds':0,
                'max_requests_total':12,'max_history_age_seconds':300})
            assurance = run_workflow_assurance(plan, history=history)
        original = copy.deepcopy(assurance)
        snapshot = freeze_assessment([], {'title':'Finite workflow assurance'}, assurances=[assurance])
        self.assertEqual(assurance, original)
        self.assertEqual(verify_assessment(snapshot), [])
        self.assertEqual(assurance['completed_cycles'], 2)
        self.assertEqual(assurance['budget_ledger']['dispatched_total'], 12)
        self.assertEqual(len(snapshot['workflows']), 2)
        # Reusing explicit traces in a frozen snapshot does not duplicate cycles.
        repeated = freeze_assessment([], snapshot['metadata'], workflows=snapshot['workflows'], assurances=[assurance])
        self.assertEqual(snapshot, repeated)
        html = render_assessment_html(snapshot)
        for cycle in assurance['cycles']:
            self.assertIn(cycle['history']['record_sha256'], html)
            self.assertIn(cycle['trace']['workflow_digest'], html)
        self.assertIn('cycle_limit', html)
        private, public = self.root/'private.pem', self.root/'trusted.pem'
        generate_keypair(private, public)
        formats = ('json','html','pdf') if PDF_AVAILABLE else ('json','html')
        create_assessment_bundle(snapshot, self.root/'assurance-proof', private, formats)
        self.assertEqual(verify_bundle(self.root/'assurance-proof', public), [])
        altered = copy.deepcopy(assurance)
        altered['cycles'][0]['history']['record_sha256'] = '0'*64
        from authzledger.oracles import seal
        altered = seal('workflow-assurance-result', altered, 'assurance_digest')
        with self.assertRaisesRegex(ValueError, 'invalid workflow assurance'):
            freeze_assessment([], {}, assurances=[altered])

    def test_absent_assurance_preserves_existing_snapshot_bytes(self):
        from authzledger.assessment_reports import _canonical
        first = freeze_assessment([self.execution], {'title':'Compatibility'})
        explicit_empty = freeze_assessment([self.execution], {'title':'Compatibility'}, assurances=[])
        self.assertNotIn('assurances', first)
        self.assertEqual(_canonical(first), _canonical(explicit_empty))
        self.assertEqual(render_assessment_html(first),render_assessment_html(explicit_empty))

    @unittest.skipUnless(PDF_AVAILABLE,'reports extra not installed')
    def test_50_findings_long_titles_unicode_and_urls_render_completely(self):
        executions=[]
        with fixture_service() as (url,state):
            for i in range(50):
                spec=fixture_spec(url);spec['rule']['id']=f'isolated-rule-{i:02d}'
                spec['title']=f'Finding {i:02d}: Überprüfung von Mandantengrenzen αβγ - '+('long context '*10)
                executions.append(execute_experiment(compile_experiment(spec)))
        snapshot=freeze_assessment(executions,{'title':'50 findings / Unicode Zürich αβγ', 'limitations':['https://example.invalid/'+('path-segment/'*40)]})
        pdf=render_assessment_pdf(snapshot)
        self.assertEqual(sum(snapshot['summary'].values()),50)
        try:from pypdf import PdfReader
        except ImportError:return
        import io
        text='\n'.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages)
        for row in snapshot['findings']:
            self.assertIn(row['id'],text)
            self.assertIn(row['record']['evidence_refs'][0],text)
        self.assertIn('Finding 49',text)

if __name__=='__main__':unittest.main()

"""One frozen assessment view for discovery, experiments, retests and handover.

Historical artifacts are retained verbatim. Computed inventory is reconstructed
by the main verifier; the standalone signature verifier establishes byte/key
integrity only. A snapshot anchor is explicitly not a fabricated network run.
"""
from __future__ import annotations

import copy
import hashlib
import html
import importlib
import io
import json
from pathlib import Path
import re
import shutil

from .oracles import canonical, seal
from .assessment_reports import validate_cvss_vector, reporting_catalog, _text

RENDERER_PROFILE = 'platform-html-pdf-v1-reportlab-4.4.9-dejavu-2.37'
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
_LIMITATIONS = [
    'Coverage is limited to retained artifacts and explicitly configured experiments; no whole-application safety percentage is calculated.',
    'Discovery and product/version matches are observations or hints, not confirmed vulnerabilities.',
    'Finding verdict, evidence level, technical severity, business risk and review decisions are separate dimensions.',
    'A missing endpoint, failed control, expired session or absent retest does not establish a fix.',
    'Retained evidence is historical unless an explicit source-bound comparison establishes a newer result; omitted cases remain not_retested.',
    'Signatures authenticate retained bytes and an independently trusted signing key, not remote execution truth, authorization ownership or completeness.',
    'The standalone verifier provides integrity_only. AuthzLedger main verification additionally reconstructs typed artifacts and exact report exports.',
    'Selected response projections remain signer-attested in their relation to omitted raw response bytes.',
    'The current assessment scope does not retroactively authorize imported historical executions; each retained execution keeps its original scope and provenance.',
    'Standards references are reviewed partial mappings, not certification or complete compliance.',
]
_SENSITIVE_KEYS = {'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'password', 'passwd',
                   'access_token', 'refresh_token', 'client_secret', 'api_key', 'x-api-key'}


def _no_credentials(value):
    """Reject known literal credential slots; source validators enforce projections."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > 96:
            raise ValueError('platform artifact nesting limit exceeded')
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key).lower() in _SENSITIVE_KEYS:
                    reference = isinstance(child, dict) and set(child) <= {'env', 'session'} and bool(child)
                    redacted = child in ('[REDACTED]', None, '') if not isinstance(child, (dict, list)) else False
                    if not reference and not redacted:
                        raise ValueError('literal credential material is not permitted in platform artifacts')
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str) and ('PRIVATE KEY-----' in item or re.search(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}', item)):
            raise ValueError('credential material is not permitted in platform artifacts')


def _verify_artifact(value):
    if not isinstance(value, dict):
        raise ValueError('platform artifact must be a typed object')
    kind = value.get('kind')
    checks = {
        'experiment-execution': ('experiments', 'verify_execution'),
        'experiment-plan': ('experiments', 'verify_plan'),
        'workflow-trace': ('workflows', 'verify_workflow'),
        'workflow-assurance-result': ('workflow_assurance', 'verify_workflow_assurance'),
        'reduction-trace': ('minimize', 'verify_reduction'),
        'surface-catalog': ('surface', 'verify_catalog'),
        'experiment-candidates': ('surface', 'verify_candidates'),
        'surface-delta': ('surface', 'verify_surface_delta'),
        'delta-check-plan': ('surface', 'verify_delta_check_plan'),
        'discovery-plan': ('discovery', 'verify_discovery_plan'),
        'discovery-execution': ('discovery', 'verify_discovery'),
        'check-plan': ('detectors', 'verify_check_plan'),
        'check-execution': ('detectors', 'verify_check_execution'),
        'playbook-plan': ('playbooks', 'verify_playbook_plan'),
        'playbook-execution': ('playbooks', 'verify_playbook'),
        'adapter-receipt': ('adapters', 'verify_adapter_receipt'),
        'knowledge-pack': ('knowledge', 'verify_knowledge_pack'),
        'knowledge-result': ('knowledge', 'verify_knowledge_result'),
        'assessment-snapshot': ('assessment_reports', 'verify_assessment'),
    }
    if kind in checks:
        module, name = checks[kind]
        validator = getattr(importlib.import_module('.' + module, __package__), name)
        errors = validator(value)
        if errors:
            raise ValueError('invalid ' + kind + ': ' + '; '.join(errors))
    elif kind == 'workflow-plan':
        from .workflows import compile_workflow
        if canonical(compile_workflow(value['spec'])) != canonical(value):
            raise ValueError('workflow plan differs from source spec')
    elif kind == 'workflow-assurance-plan':
        from .workflow_assurance import compile_workflow_assurance
        if canonical(compile_workflow_assurance(value['spec'])) != canonical(value):
            raise ValueError('workflow assurance plan differs from source spec')
    elif kind == 'reduction-plan':
        from .minimize import plan_reduction
        if canonical(plan_reduction(value['original_execution'], value['units'], max_requests=value['max_requests'])) != canonical(value):
            raise ValueError('reduction plan differs from retained original execution')
    elif kind == 'import-batch':
        from .imports import _digest, _resolve_imported_entry, PROFILES
        if value.get('schema_version') != 1 or value.get('format_profile') not in PROFILES or not isinstance(value.get('entries'), list):
            raise ValueError('invalid import batch')
        if _digest({k: v for k, v in value.items() if k != 'import_sha256'}) != value.get('import_sha256'):
            raise ValueError('import projection digest mismatch')
        for entry in value['entries']:
            _resolve_imported_entry(entry, {})
    elif kind in {'experiment-comparison', 'check-comparison'}:
        # Validation requires both actual retained sources and is performed below.
        pass
    else:
        raise ValueError('unsupported typed platform artifact')
    _no_credentials(value)


def _source_digest(value):
    for key in ('execution_digest', 'workflow_digest', 'catalog_digest', 'candidate_digest', 'delta_digest',
                'plan_digest', 'comparison_digest', 'assurance_digest', 'reduction_digest', 'result_digest',
                'pack_digest', 'snapshot_digest', 'receipt_digest', 'import_sha256'):
        if key in value:
            return value[key]
    return hashlib.sha256(canonical(value)).hexdigest()


def _finding(artifact, finding, *, reproduction=None, controls=None, observations=None):
    fid = finding.get('id', finding.get('finding_id'))
    _text(fid, 'finding identifier', limit=512)
    status = finding.get('status', finding.get('verdict', 'inconclusive'))
    level = finding.get('evidence_level')
    if level is None:
        level = 'confirmed' if status == 'confirmed' else 'inconclusive' if finding.get('interpretation') == 'inconclusive' else 'hint'
    refs = finding.get('observation_refs', finding.get('evidence_refs', []))
    record_id = 'record-' + hashlib.sha256(canonical([_source_digest(artifact['value']), fid])).hexdigest()[:32]
    return {'id': record_id, 'finding_id': fid, 'artifact_id': artifact['artifact_id'],
        'artifact_refs': [{'artifact_id': artifact['artifact_id'], 'included': artifact['included'], 'exclusion_reason': artifact['exclusion_reason']}],
        'artifact_kind': artifact['value']['kind'], 'source_digest': _source_digest(artifact['value']),
        'title': finding.get('title', finding.get('check_id', fid)), 'status': status, 'evidence_level': level,
        'interpretation': finding.get('interpretation', finding.get('verdict', status)),
        'reason': finding.get('reason', 'See retained observation and oracle decision.'),
        'control_refs': copy.deepcopy(finding.get('control_refs', [])),
        'controls': copy.deepcopy(controls if controls is not None else finding.get('controls', [])),
        'observation_refs': copy.deepcopy(refs), 'observations': copy.deepcopy(observations or []),
        'verification_level': finding.get('verification_level', 'source_attested'),
        'reproduction': copy.deepcopy(reproduction),
        'severity': finding.get('severity', 'not_assessed'),
        'severity_basis': finding.get('severity_basis', 'not_assessed' if finding.get('severity', 'not_assessed') == 'not_assessed' else 'source_attested'),
        'cvss': validate_cvss_vector(finding['cvss_vector']) if finding.get('cvss_vector') else {'version': '4.0', 'vector': None, 'score': None, 'status': 'not_scored'},
        'standard_refs': [], 'business_risk': 'not_assessed', 'impact': None,
        'remediation': None, 'remediation_basis': 'not_provided',
        'included': artifact['included'], 'exclusion_reason': artifact['exclusion_reason'],
        'review': 'unreviewed', 'retests': [], 'retest_status': 'not_retested',
        'record': copy.deepcopy(finding)}


def _rows(artifact):
    value, kind = artifact['value'], artifact['value']['kind']
    rows = []
    if kind in {'experiment-execution', 'check-execution'}:
        observations = value.get('observations', [])
        if kind == 'experiment-execution':
            cases = {c['id']: c for c in value['contract']['cases']}
            for finding in value['findings']:
                case = cases[finding['case_id']]
                controls = [r for r in value['report']['results'] if r['id'] in finding['control_refs']]
                selected = [o for o in observations if o['observation_digest'] in finding['evidence_refs']]
                reproduction = {'contract_sha256': value['report']['contract_sha256'], 'case': case,
                                'required_controls': finding['control_refs'], 'credential_values': 'resolve_at_runtime'}
                rows.append(_finding(artifact, finding, reproduction=reproduction, controls=controls, observations=selected))
        else:
            for finding in value.get('findings', []):
                refs = set(finding.get('observation_refs', finding.get('evidence_refs', [])))
                selected = [o for o in observations if o.get('observation_digest', o.get('id')) in refs]
                child = value.get('adapter_execution', {})
                controls = [r for r in value.get('report', child.get('report', {})).get('results', []) if r['id'] in finding['control_refs']]
                if child.get('kind') == 'workflow-trace':
                    variant = next((v for v in child['variants'] if v['id'] == finding['local_id']), None)
                    controls = [variant['controls']] if variant and variant.get('controls') else []
                    selected = [s for s in variant['steps'] if s['report']['evidence']['root_sha256'] in refs] if variant else []
                rows.append(_finding(artifact, finding, reproduction=value.get('reproducer'),
                                     controls=controls, observations=selected))
    elif kind == 'workflow-trace':
        for variant in value['variants']:
            state = variant['interpretation']
            f = {'id': 'workflow-' + value['workflow_digest'][:24] + ':' + variant['id'],
                 'title': value['plan']['spec']['title'] + ' / ' + variant['id'],
                 'status': 'confirmed' if state == 'violation' else 'rejected' if state == 'satisfied' else 'inconclusive',
                 'interpretation': state, 'controls_valid': variant['controls_valid'], 'reason': variant.get('reason', state),
                 'verification_level': 'evaluation_attested',
                 'control_refs': [variant['controls']['report']['evidence']['root_sha256']] if variant.get('controls') else [],
                 'evidence_refs': [s['report']['evidence']['root_sha256'] for s in variant['steps']]}
            rows.append(_finding(artifact, f, reproduction={'plan_digest': value['plan']['plan_digest'], 'variant_id': variant['id'],
                'steps': [{'step_id': s['step_id'], 'attempt': s['attempt'], 'kind': s['kind']} for s in variant['steps']]},
                controls=variant.get('controls'), observations=variant['steps']))
    elif kind == 'knowledge-result':
        for candidate in value['candidates']:
            rows.append(_finding(artifact, {**candidate, 'observation_refs': [candidate['source_ref']],
                                          'verification_level': 'product_version_hint'},
                                 reproduction={'kind': 'offline-version-match', 'pack_digest': value['pack']['pack_digest'],
                                               'does_not_execute_vulnerability_test': True}))
    elif kind == 'adapter-receipt':
        for record in value['records']:
            if record.get('state') != 'reported_match':
                continue  # A port or observed service is inventory, not a finding.
            finding = {**record, 'id': record['record_id'], 'status': 'hint', 'evidence_level': 'hint',
                       'interpretation': 'inconclusive', 'reason': 'external_scanner_claim_requires_controlled_validation',
                       'severity': 'not_assessed', 'control_refs': [], 'observation_refs': [record['record_id']],
                       'verification_level': 'source_attested'}
            rows.append(_finding(artifact, finding, controls=[], observations=[record],
                reproduction={'kind': 'external-hint-review', 'executable': False,
                              'source_projection_digest': value['source_projection_digest'],
                              'reason': 'Prepare an explicit scoped check with controls; an imported claim is not a reproducer.'}))
    elif kind in {'assessment-snapshot', 'workflow-assurance-result', 'reduction-trace', 'playbook-execution'}:
        for execution in _contained_executions(value):
            rows.extend(_rows({**artifact, 'value': execution}))
    return rows


def _contained_executions(value):
    """Enumerate retained execution sources once within a composite artifact."""
    kind = value.get('kind')
    if kind == 'assessment-snapshot':
        children = [*value['executions'], *value['workflows'], *value.get('reductions', []), *value.get('assurances', [])]
    elif kind == 'workflow-assurance-result':
        children = [cycle['trace'] for cycle in value['cycles']]
    elif kind == 'reduction-trace':
        children = [value['original_execution'], value['accepted_execution'],
                    *[attempt['execution'] for attempt in value['attempts'] if attempt.get('execution')]]
    elif kind == 'playbook-execution':
        children = [step['execution'] for step in value['steps'] if step.get('execution') is not None]
    else:
        children = [value]
    output, seen = [], set()
    for child in children:
        nested = _contained_executions(child) if child.get('kind') in {'assessment-snapshot', 'workflow-assurance-result', 'reduction-trace', 'playbook-execution'} else [child]
        for execution in nested:
            key = _source_digest(execution)
            if key not in seen:
                seen.add(key); output.append(execution)
    return output


def _comparisons(values, artifacts):
    by_digest = {_source_digest(value): value for a in artifacts for value in [a['value'], *_contained_executions(a['value'])]}
    output, seen = [], set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError('comparison must be a typed object')
        kind = value.get('kind')
        before_digest = value.get('baseline_execution_digest')
        after_digest = value.get('current_execution_digest')
        before, after = by_digest.get(before_digest), by_digest.get(after_digest)
        if before is None or (after_digest is not None and after is None):
            raise ValueError('comparison source is not retained in this platform snapshot')
        if kind == 'experiment-comparison':
            from .experiments import compare_executions
            if after is None:
                raise ValueError('experiment comparison requires retained current execution')
            expected = compare_executions(before, after)
        elif kind == 'check-comparison':
            from .detectors import compare_check_executions
            expected = compare_check_executions(before, after)
        else:
            raise ValueError('unsupported platform comparison kind')
        if canonical(value) != canonical(expected):
            raise ValueError('comparison does not match retained source executions')
        key = _source_digest(value)
        if key in seen:
            continue
        seen.add(key); output.append(copy.deepcopy(value))
    return sorted(output, key=_source_digest)


def freeze_platform(assessment, artifacts, *, comparisons=None):
    """Freeze all typed sources, inclusion decisions and honest coverage offline."""
    if not isinstance(assessment, dict) or not isinstance(artifacts, list) or len(artifacts) > 1000:
        raise ValueError('invalid platform assessment or artifact inventory')
    meta = {k: copy.deepcopy(assessment[k]) for k in ('id', 'title', 'revision', 'scope') if k in assessment}
    _text(meta.get('id'), 'assessment id', limit=256); _text(meta.get('title'), 'assessment title', limit=1024)
    if type(meta.get('revision')) is not int or meta['revision'] < 0 or not isinstance(meta.get('scope'), dict):
        raise ValueError('platform assessment requires scope and nonnegative revision')
    from .scope import validate_scope
    scope = validate_scope(meta['scope'])
    if canonical(scope) != canonical(meta['scope']):
        meta['scope'] = scope
    if 'engagement' in assessment:
        engagement = assessment['engagement']
        if not isinstance(engagement, dict) or set(engagement) - {'reference', 'roe_ref', 'notes'}:
            raise ValueError('invalid engagement metadata')
        meta['engagement'] = {key: _text(value, 'engagement ' + key, limit=2000 if key == 'notes' else 256)
                              for key, value in engagement.items()}
    _no_credentials(meta)
    retained, seen = [], set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or 'value' not in artifact:
            raise ValueError('invalid platform artifact wrapper')
        aid = _text(artifact.get('artifact_id'), 'artifact id', limit=256)
        if aid in seen:
            raise ValueError('duplicate platform artifact id')
        seen.add(aid)
        _verify_artifact(artifact['value'])
        included = artifact.get('included', True)
        if type(included) is not bool:
            raise ValueError('artifact inclusion must be boolean')
        reason = artifact.get('exclusion_reason')
        if not included:
            _text(reason, 'artifact exclusion reason')
        elif reason is not None:
            raise ValueError('included artifact cannot have an exclusion reason')
        retained.append({'artifact_id': aid, 'kind': artifact['value']['kind'], 'value': copy.deepcopy(artifact['value']),
                         'included': included, 'exclusion_reason': reason})
    retained.sort(key=lambda a: a['artifact_id'])
    comparisons = [] if comparisons is None else comparisons
    if not isinstance(comparisons, list) or len(comparisons) > 1000:
        raise ValueError('invalid platform comparisons')
    nested_comps = [comp for a in retained if a['kind'] == 'assessment-snapshot'
                    for comp in a['value']['comparisons'] if comp.get('kind') == 'experiment-comparison']
    comps = _comparisons([*comparisons, *nested_comps,
                          *[a['value'] for a in retained if a['kind'] in {'experiment-comparison', 'check-comparison'}]], retained)
    by_id = {}
    for artifact in retained:
        for row in _rows(artifact):
            old = by_id.get(row['id'])
            if old is None:
                by_id[row['id']] = row
            else:
                # Same execution retained directly and inside a playbook is one
                # evidence record, while every source inclusion decision remains.
                if old['record'] != row['record']:
                    raise ValueError('conflicting platform finding source')
                old['artifact_refs'].extend(row['artifact_refs'])
                old['included'] = old['included'] or row['included']
                old['exclusion_reason'] = None if old['included'] else '; '.join(sorted({r['exclusion_reason'] for r in old['artifact_refs']}))
    findings = sorted(by_id.values(), key=lambda row: row['id'])
    annotations = assessment.get('finding_annotations', {})
    if not isinstance(annotations, dict) or set(annotations) - {f['id'] for f in findings}:
        raise ValueError('finding annotation references absent inventory item')
    from .knowledge import validate_standard_refs
    for row in findings:
        annotation = annotations.get(row['id'], {})
        allowed = {'included', 'exclusion_reason', 'severity', 'cvss_vector', 'standard_refs', 'business_risk', 'review', 'rationale', 'impact', 'remediation'}
        if not isinstance(annotation, dict) or set(annotation) - allowed:
            raise ValueError('invalid finding annotation; computed verdicts cannot be overridden')
        if 'included' in annotation:
            if type(annotation['included']) is not bool:
                raise ValueError('finding inclusion must be boolean')
            row['included'] = annotation['included']
            row['exclusion_reason'] = annotation.get('exclusion_reason')
            if not row['included']:
                _text(row['exclusion_reason'], 'finding exclusion reason')
            elif row['exclusion_reason'] is not None:
                raise ValueError('included finding cannot have an exclusion reason')
        elif 'exclusion_reason' in annotation:
            raise ValueError('exclusion reason requires an explicit inclusion decision')
        if 'severity' in annotation:
            if annotation['severity'] not in {'critical', 'high', 'medium', 'low', 'info', 'not_assessed'}:
                raise ValueError('invalid technical severity')
            _text(annotation.get('rationale'), 'severity rationale')
            row['severity'] = annotation['severity']; row['severity_rationale'] = annotation['rationale']
            row['severity_basis'] = 'reviewed_assessment_annotation'
        if 'cvss_vector' in annotation:
            row['cvss'] = validate_cvss_vector(annotation['cvss_vector'])
        if 'business_risk' in annotation:
            row['business_risk'] = _text(annotation['business_risk'], 'business risk')
        if 'impact' in annotation:
            row['impact'] = _text(annotation['impact'], 'impact', limit=8000)
        if 'remediation' in annotation:
            row['remediation'] = _text(annotation['remediation'], 'remediation', limit=8000)
            row['remediation_basis'] = 'assessment_annotation_not_verified_fix'
        if 'review' in annotation:
            if annotation['review'] not in {'unreviewed', 'reviewed', 'accepted_risk', 'false_positive'}:
                raise ValueError('invalid review decision')
            _text(annotation.get('rationale'), 'review rationale')
            row['review'] = annotation['review']; row['review_rationale'] = annotation['rationale']
        row['standard_refs'] = validate_standard_refs(annotation.get('standard_refs', []), row['observation_refs'])
        for comp in comps:
            if row['source_digest'] not in {comp.get('baseline_execution_digest'), comp.get('current_execution_digest')}:
                continue
            for transition in comp.get('transitions', []):
                tid = transition.get('finding_id', transition.get('id'))
                if tid == row['finding_id'] or (transition.get('case_id') is not None and transition['case_id'] == row['record'].get('case_id')):
                    row['retests'].append({'comparison_digest': _source_digest(comp), 'transition': copy.deepcopy(transition)})
        if row['retests']:
            states = sorted({r['transition']['status'] for r in row['retests']})
            row['retest_status'] = states[0] if len(states) == 1 else 'multiple_historical_transitions'
    meta['finding_annotations'] = copy.deepcopy(annotations)
    inventory = [{'artifact_id': a['artifact_id'], 'kind': a['kind'], 'source_digest': _source_digest(a['value']),
                  'included': a['included'], 'exclusion_reason': a['exclusion_reason'],
                  'finding_records': sum(any(r['artifact_id'] == a['artifact_id'] for r in f['artifact_refs']) for f in findings)} for a in retained]
    coverage = [{'artifact_id': a['artifact_id'], 'kind': a['kind'],
                 'coverage': copy.deepcopy(a['value'].get('coverage', a['value'].get('comparison_envelope', {}).get('coverage', {}))),
                 'activity': 'executed' if a['kind'] in {'check-execution', 'experiment-execution', 'workflow-trace', 'discovery-execution', 'playbook-execution', 'workflow-assurance-result', 'reduction-trace'} else 'retained_offline',
                 'claim': 'Only the explicitly retained source units; discovery is not a vulnerability test.'} for a in retained]
    summary = {'artifact_count': len(retained), 'finding_records': len(findings),
               'included_finding_records': sum(f['included'] for f in findings),
               'excluded_finding_records': sum(not f['included'] for f in findings),
               'evidence_levels': {level: sum(f['evidence_level'] == level for f in findings)
                                   for level in sorted({f['evidence_level'] for f in findings})},
               'not_retested_records': sum(f['retest_status'] == 'not_retested' for f in findings),
               'counting_basis': 'Unique retained execution/finding pairs; duplicate artifact references are not counted twice. Historical records, not unique vulnerabilities or overall safety.'}
    result = seal('platform-snapshot', {'schema_id': 'authzledger.platform-snapshot', 'schema_version': 1,
        'kind': 'platform-snapshot', 'renderer_profile': RENDERER_PROFILE, 'assessment': meta, 'artifacts': retained,
        'comparisons': comps, 'inventory': inventory, 'findings': findings, 'coverage': coverage, 'summary': summary,
        'standards_profile': reporting_catalog(), 'limitations': list(_LIMITATIONS)}, 'snapshot_digest')
    if len(canonical(result)) > MAX_SNAPSHOT_BYTES:
        raise ValueError('platform snapshot exceeds size limit')
    _no_credentials(result)
    return result


def verify_platform(snapshot):
    try:
        expected = freeze_platform(snapshot['assessment'], snapshot['artifacts'], comparisons=snapshot['comparisons'])
        if canonical(expected) != canonical(snapshot):
            raise ValueError('platform snapshot differs from retained artifacts, coverage or reporting profile')
        return []
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError, ImportError) as exc:
        return [str(exc) or 'invalid platform snapshot']


def _require(snapshot):
    errors = verify_platform(snapshot)
    if errors:
        raise ValueError('invalid platform snapshot: ' + '; '.join(errors))


def render_platform_json(snapshot):
    _require(snapshot)
    return canonical(snapshot).decode('utf-8') + '\n'


def _display(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) if isinstance(value, (dict, list)) else str(value)


def _sections(snapshot):
    assessment = snapshot['assessment']
    status_counts = {status: sum(f['status'] == status for f in snapshot['findings']) for status in sorted({f['status'] for f in snapshot['findings']})}
    retest_counts = {status: sum(f['retest_status'] == status for f in snapshot['findings']) for status in sorted({f['retest_status'] for f in snapshot['findings']})}
    counts = lambda values: '; '.join(str(count) + ' ' + label for label, count in values.items()) or 'No retained result records.'
    yield 'Assessment and evidence overview', [('Assessment ID / revision', assessment['id'] + ' / ' + str(assessment['revision'])),
        ('Retained evidence', str(len(snapshot['artifacts'])) + ' artifacts; ' + str(len(snapshot['findings'])) + ' unique execution/finding pairs.'),
        ('Historical result records', counts(status_counts)), ('Source-bound retest records', counts(retest_counts)),
        ('Interpretation', 'Historical verdicts remain visible after retesting. These counts do not measure whole-application safety.'),
        ('Snapshot digest', snapshot['snapshot_digest'])]
    scope = assessment['scope']
    yield 'Scope and authorization', [('Authorization reference', scope['authorization_ref']), ('Scope ID', scope['id']),
        ('Expires at', scope['expires_at']), ('Allowed origins', '\n'.join(scope['origins'])),
        ('Approved operations', '\n'.join(op['method'] + ' ' + op['origin'] + op['path'] + ' [' + op['purpose'] + ' / ' + op.get('effect', 'read') + ']' for op in scope['operations'])),
        ('Allowed networks', ', '.join(scope['allowed_networks'])), ('Execution limits', _display(scope['limits']))]
    if assessment.get('engagement'):
        yield 'Engagement and rules of engagement', [(key.replace('_', ' ').title(), value) for key, value in sorted(assessment['engagement'].items())]
    yield 'Coverage and result accounting', [('Summary', _display(snapshot['summary'])), ('Coverage', _display(snapshot['coverage']))]
    yield 'Complete included and excluded inventory', [('Artifact inventory', _display(snapshot['inventory'])),
        ('Finding inventory', _display([{k: f[k] for k in ('id', 'title', 'status', 'evidence_level', 'included', 'exclusion_reason', 'artifact_refs', 'review', 'retest_status')} for f in snapshot['findings']]))]
    seen_sources = set()
    for artifact in snapshot['artifacts']:
        for value in [artifact['value'], *_contained_executions(artifact['value'])]:
            source_digest = _source_digest(value)
            if source_digest in seen_sources:
                continue
            seen_sources.add(source_digest)
            fields = []
            kind = value['kind']
            if kind == 'surface-catalog':
                fields = [(key.replace('_', ' ').title(), _display(value[key])) for key in ('assets', 'endpoints', 'observations', 'coverage', 'limitations') if key in value]
            elif kind == 'discovery-execution':
                fields = [('Observed assets', _display(value['catalog']['assets'])), ('Observed endpoints', _display(value['catalog']['endpoints'])),
                          ('Discovery observations', _display(value['observations'])), ('Coverage', _display(value['coverage'])), ('Request ledger', _display(value['ledger']))]
            elif kind == 'adapter-receipt':
                fields = [('Import profile', value['profile']), ('External evidence projections', _display(value['records'])),
                          ('Import inventory', _display(value['inventory'])), ('Source inventory and omissions', _display(value['source_inventory'])),
                          ('Safe source projection digest', value['source_projection_digest']), ('Limitations', _display(value['limitations']))]
            elif kind == 'experiment-candidates':
                fields = [('Unexecuted experiment candidates and blockers', _display(value['candidates']))]
            elif kind == 'surface-delta':
                fields = [('Surface changes, without fix claims', _display(value['transitions']))]
            elif kind == 'delta-check-plan':
                fields = [('Offline dependency-aware selection; not yet executed', _display(value))]
            elif kind == 'playbook-execution':
                fields = [('Static playbook step outcomes', _display([{k: v for k, v in step.items() if k != 'execution'} for step in value['steps']])),
                          ('Coverage', _display(value['coverage'])), ('Shared request ledger', _display(value['budget_ledger']))]
            if fields:
                yield 'Evidence source / ' + kind, [('Source digest', source_digest), *fields]
    for row in snapshot['findings']:
        # Exclusion changes the editorial view only; original evidence remains retained.
        if not row['included']:
            continue
        fields = [('Finding record ID', row['id']), ('Original finding ID', row['finding_id']), ('Historical verdict', row['status']), ('Evidence level', row['evidence_level']),
            ('Reason', row['reason']), ('Interpretation', row['interpretation']), ('Technical severity', _display(row['severity'])),
            ('Severity basis', row['severity_basis']), ('Severity rationale', row.get('severity_rationale', 'No assessment annotation.')),
            ('CVSS 4.0', _display(row['cvss'])), ('Assessed impact', row['impact'] or 'No case-specific impact assessment supplied.'),
            ('Business risk', row['business_risk']), ('Review decision', row['review']),
            ('Review rationale', row.get('review_rationale', 'No review annotation.')),
            ('Controls', _display(row['controls'])), ('Control references', _display(row['control_refs'])),
            ('Observation references', _display(row['observation_refs'])), ('Observations', _display(row['observations'])),
            ('Verification level', row['verification_level']), ('Reproduction', _display(row['reproduction'])),
            ('Remediation guidance', row['remediation'] or 'No case-specific remediation supplied. Review the retained rule and its prerequisites before selecting a fix.'),
            ('Remediation basis', row['remediation_basis']),
            ('Fix validation', 'A proposed remediation is not a verified fix. Use fresh credentials and the retained source-bound recipe, rerun its required controls, and retain the comparison; omitted cases remain not_retested.'),
            ('Source digest', row['source_digest']), ('Retest status', row['retest_status']), ('Source-bound comparisons', _display(row['retests'])),
            ('Partial standards mapping', _display(row['standard_refs']))]
        yield row['title'], fields
    yield 'Limitations and independent verification', [('Limitation', item) for item in snapshot['limitations']] + [
        ('Renderer profile', snapshot['renderer_profile']),
        ('Verify integrity', 'Use a separately trusted public key: python3 -I verify_bundle.py PACKAGE --public-key TRUSTED.pem.'),
        ('Verify semantics', 'Run AuthzLedger verify-bundle with the same trusted key. This replays retained evaluators and checks exact report bytes, not the remote application.')]


def render_platform_html(snapshot):
    _require(snapshot)
    from .reports import _document
    esc = lambda value: html.escape(str(value), quote=True)
    body = '<section class="hero"><div class="kicker">Evidence-first assessment</div><h1>' + esc(snapshot['assessment']['title']) + '</h1><p class="lead">Explicit scope. Controlled experiments. Honest coverage.</p></section>'
    for title, fields in _sections(snapshot):
        body += '<section class="panel" style="margin-top:24px"><h2>' + esc(title) + '</h2><dl>'
        body += ''.join('<dt>' + esc(key) + '</dt><dd style="white-space:pre-wrap;overflow-wrap:anywhere">' + esc(value) + '</dd>' for key, value in fields)
        body += '</dl></section>'
    return _document(snapshot['assessment']['title'], body, kind='Frozen assessment snapshot') + '\n'


def render_platform_pdf(snapshot):
    _require(snapshot)
    from .assessment_reports import _PDF_LOCK, _FONT_HASHES, _profile_pdf_canvas
    try:
        import reportlab
        if reportlab.Version != '4.4.9':
            raise ValueError('PDF profile requires reportlab==4.4.9; install AuthzLedger[reports]')
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import SimpleDocTemplate, Paragraph
    except ImportError as exc:
        raise ValueError('PDF renderer unavailable; install AuthzLedger[reports] (reportlab==4.4.9)') from exc
    with _PDF_LOCK:
        fontdir = Path(__file__).with_name('fonts')
        for name, filename in (('AuthzDejaVu', 'DejaVuSans.ttf'), ('AuthzDejaVuBold', 'DejaVuSans-Bold.ttf')):
            if hashlib.sha256((fontdir / filename).read_bytes()).hexdigest() != _FONT_HASHES[filename]:
                raise ValueError('PDF profile font integrity mismatch')
            if name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(name, str(fontdir / filename)))
        sections = list(_sections(snapshot))
        chars = pdfmetrics.getFont('AuthzDejaVu').face.charToGlyph
        for text in [str(v) for title, fields in sections for v in [title, *[x for pair in fields for x in pair]]]:
            if any(ord(c) not in chars for c in text if c not in '\n\t\r'):
                raise ValueError('PDF font does not cover every character; unsupported text must be reviewed')
        body = ParagraphStyle('PlatformBody', fontName='AuthzDejaVu', fontSize=9, leading=13.2,
                              textColor=colors.HexColor('#162338'), spaceAfter=7, splitLongWords=True)
        label = ParagraphStyle('PlatformLabel', parent=body, fontName='AuthzDejaVuBold', fontSize=8, leading=11,
                               textColor=colors.HexColor('#52688d'), spaceBefore=6, spaceAfter=3, keepWithNext=True)
        heading = ParagraphStyle('PlatformHeading', parent=body, fontName='AuthzDejaVuBold', fontSize=17, leading=21,
                                 spaceBefore=22, spaceAfter=13, keepWithNext=True)
        title_style = ParagraphStyle('PlatformTitle', parent=heading, fontSize=29, leading=35, spaceAfter=26)
        esc = lambda value: html.escape(str(value), quote=False).replace('\n', '<br/>')
        story = [Paragraph('AUTHZLEDGER / ASSESSMENT EVIDENCE', label), Paragraph(esc(snapshot['assessment']['title']), title_style)]
        for title, fields in sections:
            story.append(Paragraph(esc(title), heading))
            for key, value in fields:
                story.extend([Paragraph(esc(key), label), Paragraph(esc(value), body)])
        buffer = io.BytesIO()
        document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=48, leftMargin=48, topMargin=52, bottomMargin=48,
            title=snapshot['assessment']['title'], author='AuthzLedger', subject='Scoped evidence-first assessment',
            creator=RENDERER_PROFILE, pageCompression=1, invariant=1)
        def page(canvas, doc):
            canvas.saveState(); canvas.setStrokeColor(colors.HexColor('#3d66d9')); canvas.setLineWidth(2)
            canvas.line(48, A4[1] - 32, A4[0] - 48, A4[1] - 32)
            canvas.setFillColor(colors.HexColor('#52688d')); canvas.setFont('AuthzDejaVu', 7)
            canvas.drawString(48, 25, 'AuthzLedger | ' + snapshot['snapshot_digest'][:24])
            canvas.drawRightString(A4[0] - 48, 25, f'Page {doc.page}'); canvas.restoreState()
        document.build(story, onFirstPage=page, onLaterPages=page, canvasmaker=_profile_pdf_canvas)
        return buffer.getvalue()


def platform_attachments(snapshot, formats=('json', 'html', 'pdf')):
    selected = tuple(formats)
    if not selected or len(set(selected)) != len(selected) or set(selected) - {'json', 'html', 'pdf'}:
        raise ValueError('formats must be unique json/html/pdf values')
    result = {'platform.json': render_platform_json(snapshot).encode('utf-8')}
    if 'html' in selected:
        result['platform.html'] = render_platform_html(snapshot).encode('utf-8')
    if 'pdf' in selected:
        result['platform.pdf'] = render_platform_pdf(snapshot)
    return result


def export_platform(snapshot, out, formats=('json', 'html', 'pdf')):
    from .signing import _no_symlink_components, _write_new
    destination = Path(out).absolute(); _no_symlink_components(destination)
    if destination.exists():
        raise ValueError('platform export destination already exists')
    files = platform_attachments(snapshot, formats)
    destination.mkdir(mode=0o700, parents=False)
    try:
        for name, raw in files.items():
            _write_new(destination / name, raw)
    except BaseException:
        shutil.rmtree(destination); raise
    return {name: destination / name for name in files}


def platform_anchor(snapshot):
    _require(snapshot)
    scope_digest = hashlib.sha256(canonical(snapshot['assessment']['scope'])).hexdigest()
    return {'schema_version': 1, 'kind': 'platform-anchor', 'snapshot_digest': snapshot['snapshot_digest'],
            'scope_digest': scope_digest, 'contract_sha256': scope_digest,
            'evidence': {'root_sha256': snapshot['snapshot_digest']}, 'claim': 'frozen_assessment_snapshot_not_network_execution'}


def verify_platform_anchor(anchor):
    fields = {'schema_version', 'kind', 'snapshot_digest', 'scope_digest', 'contract_sha256', 'evidence', 'claim'}
    if not isinstance(anchor, dict) or set(anchor) != fields or type(anchor.get('schema_version')) is not int or anchor['schema_version'] != 1 or anchor.get('kind') != 'platform-anchor':
        return ['invalid platform anchor schema']
    if any(not isinstance(anchor.get(key), str) or not re.fullmatch('[0-9a-f]{64}', anchor[key]) for key in ('snapshot_digest', 'scope_digest')):
        return ['invalid platform anchor digest']
    if anchor['evidence'] != {'root_sha256': anchor['snapshot_digest']} or anchor['contract_sha256'] != anchor['scope_digest'] or anchor['claim'] != 'frozen_assessment_snapshot_not_network_execution':
        return ['platform anchor binding mismatch']
    return []


def create_platform_bundle(snapshot, out, key, formats=('json', 'html', 'pdf')):
    from .signing import create_bundle
    return create_bundle(platform_anchor(snapshot), out, key, platform_attachments(snapshot, formats))


def verify_platform_attachments(report, contents):
    from .signing import _json
    name = 'attachments/platform.json'
    visuals = {'attachments/platform.html', 'attachments/platform.pdf'}
    if (visuals.intersection(contents) or report.get('kind') == 'platform-anchor') and name not in contents:
        raise ValueError('platform anchor and visual exports require platform.json')
    if name not in contents:
        return
    if len(contents[name]) > MAX_SNAPSHOT_BYTES:
        raise ValueError('reserved platform snapshot exceeds size limit')
    snapshot = _json(contents[name]); _require(snapshot)
    if canonical(platform_anchor(snapshot)) != canonical(report):
        raise ValueError('platform snapshot does not match signed anchor')
    if contents[name] != render_platform_json(snapshot).encode('utf-8'):
        raise ValueError('platform.json is not the canonical snapshot export')
    for suffix, renderer in (('html', render_platform_html), ('pdf', render_platform_pdf)):
        path = 'attachments/platform.' + suffix
        if path in contents:
            expected = renderer(snapshot)
            if isinstance(expected, str):
                expected = expected.encode('utf-8')
            if contents[path] != expected:
                raise ValueError('platform.' + suffix + ' does not match retained snapshot')

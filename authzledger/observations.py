"""Credential-free oracle projections bound to the original report roots."""
from __future__ import annotations
import hashlib
from .oracles import canonical, capture_input, evaluate_input, seal

def make_observation(*, plan, execution_id, case, result, capture, report_root, controls_valid, control_refs, secret_values=()):
    observed = capture_input(plan['rule'], capture)
    def contains_secret(value):
        if isinstance(value,str): return any(secret and secret in value for secret in secret_values)
        if isinstance(value,dict): return any(contains_secret(k) or contains_secret(v) for k,v in value.items())
        if isinstance(value,list): return any(contains_secret(v) for v in value)
        return False
    if contains_secret(observed): observed={'present':False,'error':'credential_reflection_redacted'}
    decision = evaluate_input(plan['rule'], observed)
    if not controls_valid:
        decision = {'interpretation':'inconclusive','reason':'invalid_controls'}
    safe = plan['spec']['capture_mode'] == 'safe_values'
    # No raw capture, headers, credential values or low-entropy secret hashes.
    oracle = {'oracle_id':plan['rule']['kind'],'oracle_version':1,'decision':decision,
              'input': observed if safe else None,
              'input_retained':safe}
    projection = {k:v for k,v in case.items() if k not in {'expect'}}
    item = {'schema_id':'authzledger.observation','schema_version':1,'kind':'observation',
            'plan_digest':plan['plan_digest'],'execution_id':execution_id,'case_id':case['id'],
            'attempt_id':case['id'] + ':1','contract_digest':plan['contract_digest'],
            'report_root':report_root,'request_projection_digest':hashlib.sha256(canonical(projection)).hexdigest(),
            'capture_profile':'selected-values-v1' if safe else 'predicate-attestation-v1',
            'body_sha256':result.get('response_sha256'),'status':result.get('status'),
            'body_complete':bool(capture and capture.get('complete')),
            'headers_retained':False,'rule_digest':plan['rule_digest'],
            'normalization_digest':plan['normalization_digest'],'oracle':oracle,
            'control_refs':control_refs,'controls_valid':controls_valid,
            'interpretation':decision['interpretation'],
            'verification_level':'captured_inputs_replayed' if safe else 'evaluation_attested',
            'limitations':['Remote response authenticity is not established by local signing.',
                           'Only selected oracle inputs are replayed; their projection from the omitted raw body remains signer-attested.' if safe else 'Predicate values are not retained; evaluation is signer-attested.']}
    return seal('observation',item,'observation_digest')

"""Pure, bounded and versioned predicates; no network or executable expressions."""
from __future__ import annotations
import copy
import hashlib
import json
from .model import _pointer, _json_value

class OracleError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('utf-8')

def digest(kind, value, field=None):
    data = {k: v for k, v in value.items() if k != field} if field else value
    return hashlib.sha256(('AuthzLedger:' + kind + ':v1\n').encode() + canonical(data)).hexdigest()

def seal(kind, value, field):
    result = copy.deepcopy(value)
    result[field] = digest(kind, result, field)
    return result

def equal(left, right):
    # JSON numbers compare by value, but booleans and numbers never alias.
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if type(left) in {int, float} and type(right) in {int, float}:
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(equal(v, right[k]) for k, v in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    return left == right

def pointer(document, path):
    _pointer(path)
    value = document
    if path == '':
        return True, value
    for part in path[1:].split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isascii() and part.isdecimal() and (part == '0' or not part.startswith('0')) and int(part) < len(value):
            value = value[int(part)]
        else:
            return False, None
    return True, value

def parse_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise OracleError('duplicate_json_key')
            result[key] = value
        return result
    def reject(_):
        raise OracleError('non_finite_json')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=reject)
        _json_value(value, 'oracle input')
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise OracleError('invalid_json_capture') from None

def validate_rule(rule):
    required = {'id', 'kind', 'resource_id'}
    allowed = required | {'pointer', 'value', 'values', 'header', 'type','resource_pointer','resource_value'}
    if not isinstance(rule, dict) or set(rule) - allowed or required - set(rule):
        raise OracleError('invalid_rule_fields')
    from .model import _identifier
    _identifier(rule['id'], 'rule id'); _identifier(rule['resource_id'], 'resource id')
    kinds = {'forbid_field_equal', 'require_field_equal', 'require_present', 'require_absent', 'require_type', 'require_member', 'forbid_member', 'require_header_equal', 'forbid_header_equal', 'require_status'}
    if rule['kind'] not in kinds:
        raise OracleError('unsupported_oracle')
    kind = rule['kind']
    needed = {'pointer'} if 'header' not in kind and kind != 'require_status' else set()
    if kind.endswith('_equal'): needed.add('value')
    if kind in {'require_member', 'forbid_member', 'require_status'}: needed.add('values')
    if kind == 'require_type': needed.add('type')
    if 'header' in kind: needed.add('header')
    if ('resource_pointer' in rule)!=('resource_value' in rule): raise OracleError('incomplete_resource_binding')
    if 'resource_pointer' in rule:
        _pointer(rule['resource_pointer']); _json_value(rule['resource_value'],'resource binding'); needed.update({'resource_pointer','resource_value'})
    if set(rule) != required | needed:
        raise OracleError('invalid_oracle_fields')
    if 'pointer' in rule: _pointer(rule['pointer'])
    if 'value' in rule: _json_value(rule['value'], 'rule value')
    if 'values' in rule:
        if not isinstance(rule['values'], list) or not 1 <= len(rule['values']) <= 100:
            raise OracleError('invalid_rule_values')
        _json_value(rule['values'], 'rule values')
    if kind == 'require_status' and any(type(s) is not int or not 100 <= s <= 599 for s in rule['values']):
        raise OracleError('invalid_status_set')
    if 'header' in rule:
        import re
        if not isinstance(rule['header'], str) or not re.fullmatch(r'[A-Za-z0-9-]{1,80}', rule['header']):
            raise OracleError('invalid_header')
        if any(word in rule['header'].lower() for word in ('cookie','authorization','token','secret','key','session')):
            raise OracleError('sensitive_header_oracle_unsupported')
    if 'type' in rule and rule['type'] not in {'null','boolean','number','string','array','object'}:
        raise OracleError('invalid_json_type')
    return copy.deepcopy(rule)

def evaluate_input(rule, observed):
    """Evaluate an explicit value projection, retaining missing versus JSON null."""
    validate_rule(rule)
    kind = rule['kind']; present = observed.get('present', False); value = observed.get('value')
    if observed.get('error'):
        return {'interpretation':'inconclusive', 'reason':observed['error']}
    if kind in {'forbid_field_equal','forbid_header_equal'}:
        violation = present and equal(value, rule['value'])
    elif kind in {'require_field_equal','require_header_equal'}:
        violation = not present or not equal(value, rule['value'])
    elif kind == 'require_present': violation = not present
    elif kind == 'require_absent': violation = present
    elif kind == 'require_type':
        types = {'null':type(None),'boolean':bool,'number':(int,float),'string':str,'array':list,'object':dict}
        violation = not present or not isinstance(value, types[rule['type']]) or (rule['type']=='number' and isinstance(value,bool))
    elif kind in {'require_member','forbid_member'}:
        member = present and any(equal(value, item) for item in rule['values'])
        violation = (not member) if kind == 'require_member' else member
    else: violation = not present or value not in rule['values']
    return {'interpretation':'violation' if violation else 'satisfied', 'reason':'predicate_violated' if violation else 'predicate_satisfied'}

def capture_input(rule, capture):
    validate_rule(rule)
    if not capture or capture.get('error_code') or not capture.get('complete'):
        return {'present':False, 'error':'incomplete_capture'}
    if rule['kind'] == 'require_status':
        return {'present':True, 'value':capture['status']}
    if 'header' in rule:
        matches = [v for k,v in capture.get('headers', []) if k.lower() == rule['header'].lower()]
        if len(matches) != 1:
            return {'present':False,'error':'missing_or_duplicate_header'}
        return {'present':True,'value':matches[0]}
    try:
        document = parse_json(capture['body'])
        found, value = pointer(document, rule['pointer'])
        return {'present':found,'value':value} if found else {'present':False}
    except (KeyError, OracleError):
        return {'present':False,'error':'invalid_json_capture'}

def evaluate(rule, capture, controls, bindings=None):
    observed = capture_input(rule, capture)
    decision = evaluate_input(rule, observed)
    if not controls:
        return {'interpretation':'inconclusive','reason':'invalid_controls'}
    return decision

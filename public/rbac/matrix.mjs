// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {evaluateAccess} from './model.mjs';
import {CASE_LIMIT, normalizeQuery} from './retest.mjs';

const expectations = ['grant', 'no_grant'];
const schema = 'authzledger.rbac-matrix.v1';

// Subject groups are part of the caller context. All remaining normalized fields describe the request.
export function axes(query) {
  const {kind, name, subjectNamespace, groups, ...request} = query;
  return [JSON.stringify([kind, name, subjectNamespace || '', groups]), JSON.stringify(request)];
}
export function assessment(result, expected) {
  if (result.status === 'indeterminate') return 'uncertain';
  return (result.status === 'granted_in_snapshot') === (expected === 'grant') ? 'matches' : 'differs';
}

export function createMatrix(original) {
  let rows = [], after = null;
  function makeRow(raw, expected) {
    if (!expectations.includes(expected)) throw Error('badFile');
    const query = normalizeQuery(raw);
    const key = JSON.stringify(query);
    return {key, query, expected, before:evaluateAccess(original.model,query), after:after ? evaluateAccess(after.model,query) : null};
  }
  function observation(result, expected) {
    return result ? {status:result.status, assessment:assessment(result,expected), matching_rules:result.matchCount} : null;
  }
  return {
    get rows() { return rows; },
    get after() { return after; },
    add(query, expected) {
      const row = makeRow(query,expected);
      if (rows.some(r => r.key === row.key)) throw Error('duplicate');
      if (rows.length >= CASE_LIMIT) throw Error('limit');
      rows.push(row);
      return row.key;
    },
    setExpected(key, expected) {
      const row = rows.find(item=>item.key === key);
      if (!row || !expectations.includes(expected)) throw Error('badFile');
      row.expected = expected;
    },
    remove(key) { rows = rows.filter(row=>row.key !== key); },
    compare(source) {
      const evaluated = rows.map(row=>({...row,after:source ? evaluateAccess(source.model,row.query) : null}));
      rows = evaluated;
      after = source;
    },
    export() {
      return {schema, original_sha256:original.digest, comparison_sha256:after?.digest ?? null,
        cases:rows.map(r=>({query:r.query,expected:r.expected,before:observation(r.before,r.expected),after:observation(r.after,r.expected)}))};
    },
    restore(file) {
      if (file?.schema !== schema || !Array.isArray(file.cases) || !file.cases.length || file.cases.length > CASE_LIMIT) throw Error('badFile');
      if (file.original_sha256 !== original.digest) throw Error('wrongSource');
      const result = file.cases.map(row=>makeRow(row?.query,row?.expected));
      if (new Set(result.map(r=>r.key)).size !== result.length) throw Error('duplicate');
      rows = result;
    }
  };
}

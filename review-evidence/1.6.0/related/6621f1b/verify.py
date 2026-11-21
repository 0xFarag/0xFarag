#!/usr/bin/env python3
# ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
"""Offline regression evidence for PR #5. Run from the extracted candidate root."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import tarfile
import unittest

BASE = '03aea857e35358ddeb13d2a861b633e60c1ca873'
HEAD = '6621f1b76b3b641ae1f25a195d50cad677d96091'
MODULES = ('test_adapters150', 'test_reports', 'test_evidence_dependencies', 'test_evidence',
           'test_knowledge150', 'test_history', 'test_signing', 'test_comparison_delivery')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def historic_files(path, commit):
    with tarfile.open(path, mode='r:gz') as archive:
        prefix = '0xFarag-' + commit + '/'
        files = {}
        for member in archive:
            if not member.name.startswith(prefix) or not member.isfile():
                continue
            name = member.name[len(prefix):]
            if name.startswith(('evidence/', 'release/')):
                files[name] = digest(archive.extractfile(member).read())
    if not files or 'release/SHA256SUMS.txt' not in files:
        raise ValueError('archive commit or selected directories do not match')
    return files


class RecordingResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.passed = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test.id())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('baseline_archive', type=Path)
    parser.add_argument('candidate_archive', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    root = Path.cwd()
    baseline = historic_files(args.baseline_archive, BASE)
    candidate = historic_files(args.candidate_archive, HEAD)
    counters = {'blocked': 0, 'openssl': 0, 'isolated_verifier': 0}
    verifier = (root / 'tools/verify_bundle.py').resolve()

    def guard(event, data):
        if event in ('socket.connect', 'socket.bind', 'socket.getaddrinfo', 'socket.sendto'):
            counters['blocked'] += 1
            raise PermissionError(event)
        if event == 'subprocess.Popen':
            argv = data[1]
            if len(argv) > 1 and argv[0] == 'openssl' and argv[1] in ('genpkey', 'pkey', 'pkeyutl'):
                counters['openssl'] += 1
            elif len(argv) > 3 and argv[0] == sys.executable and argv[1] == '-I' and Path(argv[2]).resolve() == verifier:
                counters['isolated_verifier'] += 1
            else:
                counters['blocked'] += 1
                raise PermissionError('unexpected subprocess')

    with tarfile.open(args.candidate_archive) as archive:
        # Bind the exact tracked code and fixtures used in the installed working tree.
        prefix = '0xFarag-' + HEAD + '/'
        checked = 0
        for member in archive:
            if not member.isfile() or not member.name.startswith(prefix):
                continue
            rel = member.name[len(prefix):]
            if digest((root / rel).read_bytes()) != digest(archive.extractfile(member).read()):
                raise ValueError('checked-out file differs: ' + rel)
            checked += 1
    sys.addaudithook(guard)
    sys.path[:0] = [str(root / 'tests'), str(root)]
    result = RecordingResult()
    unittest.defaultTestLoader.loadTestsFromNames(MODULES).run(result)
    sums = {}
    for line in (root / 'release/SHA256SUMS.txt').read_text().splitlines():
        wanted, filename = line.split()
        sums[filename] = candidate.get('release/' + filename) == wanted
    problem = sorted(k for k in baseline.keys() | candidate.keys() if candidate.get(k) != baseline.get(k))
    ok = (not problem and all(sums.values()) and len(sums) == 2 and result.wasSuccessful()
          and not result.skipped and counters['blocked'] == 0 and result.testsRun == len(result.passed))
    out = {'rights': 'ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).',
           'scope': 'Supplemental passive historical regression and archival byte preservation on PR #5',
           'repository': '0xFarag/0xFarag', 'baseline': BASE, 'candidate': HEAD, 'release_authorized': False,
           'candidate_files_verified_before_execution': checked, 'python': platform.python_version(),
           'modules': list(MODULES), 'tests_run': result.testsRun, 'successful': len(result.passed),
           'passed_test_ids': result.passed, 'skipped': [(t.id(), reason) for t, reason in result.skipped],
           'failures': [(t.id(), msg) for t, msg in result.errors + result.failures],
           'historical_byte_comparison': {'directories': ['release/', 'evidence/'], 'baseline_count': len(baseline),
              'candidate_count': len(candidate), 'different_or_missing_paths': problem, 'sha256': candidate,
              'historical_manifest_checks': sums},
           'parent_process_guard': counters, 'result': 'passed' if ok else 'failed',
           'limits': ['Parent-process Python audit hook; isolated standalone verifier and local OpenSSL children run separately.',
                      'Only files tracked under the two named directories are compared. External release assets are outside this comparison.',
                      'Exact-head supplemental selection; not a full 1.5 or 1.6 regression, browser suite, platform installer test or release decision.']}
    args.output.write_text(json.dumps(out, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({k: out[k] for k in ('result', 'tests_run', 'successful', 'failures', 'parent_process_guard')}, ensure_ascii=False)[:1500])
    return int(not ok)


if __name__ == '__main__':
    raise SystemExit(main())

"""The passing fixture, signing key and synthetic evidence exist only in a temporary directory."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import check_release_gate as gate


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class GateCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="authz-gate-tests-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.home = Path(cls.tmp.name)
        cls.priv = cls.home/"testing-only-private.pem"
        cls.pub = cls.home/"public.pem"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519","-out",cls.priv],check=True,capture_output=True)
        subprocess.run(["openssl","pkey","-in",cls.priv,"-pubout","-out",cls.pub],check=True,capture_output=True)
        der=subprocess.check_output(["openssl","pkey","-in",cls.priv,"-pubout","-outform","DER"])
        cls.fingerprint=hashlib.sha256(der).hexdigest()
        cls.commit="a"*40

    def setUp(self):
        folder=tempfile.TemporaryDirectory(dir=self.home)
        self.addCleanup(folder.cleanup)
        self.root=Path(folder.name)
        contract=json.loads(gate.CONTRACT.read_bytes())
        self.records={}
        self.decisions={"schema":"authzledger.gate-decisions/v1","target_release":gate.RELEASE,
                        "target_commit":self.commit,"artifacts":[],"criteria":[]}
        for c in contract["required_criteria"]:
            cid=c["id"]
            rel="artifacts/"+cid+".log"
            payload=("Synthetic self-test data — "+cid+"\n").encode()
            path=self.root/rel
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(payload)
            self.decisions["artifacts"].append({"path":rel,"sha256":gate.sha(payload)})
            rc={"schema":"authzledger.criterion-receipt/v1","id":cid,"target_release":gate.RELEASE,
                "target_commit":self.commit,"positive":"passed","negative_control":"passed","reviewer":"selftest",
                "environment":"temporary test fixture","reproduction":"Synthetic verifier schema test only.","artifacts":[rel]}
            self.records[cid]=rc
            self.decisions["criteria"].append({"id":cid,"path":c["evidence_path"],"sha256":gate.sha(encode(rc)),"decision":"passed"})
            disk=self.root/c["evidence_path"]
            disk.parent.mkdir(exist_ok=True)
            disk.write_bytes(encode(rc))
        self.seal()

    def seal(self, att_changes=None):
        data=encode(self.decisions)
        (self.root/gate.DECISIONS).write_bytes(data)
        att={"schema":"authzledger.gate-attestation/v1","target_release":gate.RELEASE,"target_commit":self.commit,
             "contract_sha256":gate.CONTRACT_HASH,"decisions_sha256":gate.sha(data)}
        att.update(att_changes or {})
        (self.root/gate.ATTESTATION).write_bytes(encode(att))
        subprocess.run(["openssl","pkeyutl","-sign","-rawin","-inkey",self.priv,"-in",self.root/gate.ATTESTATION,
                        "-out",self.root/gate.SIGNATURE],check=True,capture_output=True)

    def check(self, **kwargs):
        return gate.check(self.root,kwargs.get("commit",self.commit),kwargs.get("key",self.pub),kwargs.get("fingerprint",self.fingerprint))

    def reject(self, **kwargs):
        with self.assertRaises((OSError,ValueError,TypeError,KeyError)):
            self.check(**kwargs)

    def change_record(self, **updates):
        row=self.decisions["criteria"][0]
        record=self.records[row["id"]].copy()
        record.update(updates)
        data=encode(record)
        (self.root/row["path"]).write_bytes(data)
        row["sha256"]=gate.sha(data)
        self.seal()

    def test_valid_cli_checks_actual_signature(self):
        result=subprocess.run([os.sys.executable,"-I",gate.__file__,str(self.root),"--expected-commit",self.commit,
                              "--trusted-key",str(self.pub),"--key-sha256",self.fingerprint],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr+result.stdout)
        record=json.loads(result.stdout)
        self.assertEqual(record["criteria_verified"],18)
        self.assertEqual(record["semantic_validation"],"not_performed")
        self.assertIs(record["publication_authorized"],False)

    def test_empty_cli_emits_rejected_json(self):
        shutil.rmtree(self.root)
        self.root.mkdir()
        log=io.StringIO()
        with redirect_stdout(log):
            status=gate.main([str(self.root),"--expected-commit",self.commit,"--trusted-key",str(self.pub),"--key-sha256",self.fingerprint])
        self.assertEqual(status,1)
        self.assertEqual(json.loads(log.getvalue())["formal_dossier"],"rejected")

    def test_zero_missing_duplicate_unknown_or_failed_decision(self):
        original=list(self.decisions["criteria"])
        for rows in [[],original[1:],original[:-1]+[original[0]],original[:-1]+[{**original[-1],"id":"unknown"}],
                     original[:-1]+[{**original[-1],"decision":"skipped"}]]:
            self.decisions["criteria"]=rows
            self.seal()
            self.reject()

    def test_each_receipt_checks_context_and_both_outcomes(self):
        changes=({"target_commit":"b"*40},{"id":"S16-17"},{"positive":"failed"},{"negative_control":"skipped"},
                 {"target_release":"1.5.0"},{"environment":""},{"reviewer":" "},{"reproduction":""},
                 {"artifacts":[]},{"artifacts":["artifacts/missing"]},{"artifacts":["artifacts/S16-01.log"]*2})
        for change in changes:
            self.change_record(**change)
            self.reject()

    def test_target_mismatch_and_wrong_anchor(self):
        self.reject(commit="b"*40)
        self.reject(commit=json.loads(gate.CONTRACT.read_bytes())["baseline_commit"])
        self.reject(fingerprint="0"*64)
        self.seal({"contract_sha256":"0"*64})
        self.reject()

    def test_another_independently_pinned_ed25519_key_cannot_validate_attestation(self):
        with tempfile.TemporaryDirectory(dir=self.home) as tmp:
            key=Path(tmp)/"other-private.pem"
            public=Path(tmp)/"other-public.pem"
            subprocess.run(["openssl","genpkey","-algorithm","Ed25519","-out",key],check=True,capture_output=True)
            subprocess.run(["openssl","pkey","-in",key,"-pubout","-out",public],check=True,capture_output=True)
            der=subprocess.check_output(["openssl","pkey","-in",key,"-pubout","-outform","DER"])
            self.reject(key=public,fingerprint=gate.sha(der))

    def test_real_signature_rejects_changed_bytes(self):
        p=self.root/gate.SIGNATURE
        data=p.read_bytes()
        p.write_bytes(data[:-1]+bytes([data[-1]^1]))
        self.reject()

    def test_outside_key_required(self):
        copied=self.root/"public.pem"
        shutil.copyfile(self.pub,copied)
        self.reject(key=copied)

    def test_decisions_and_raw_bytes_have_separate_digests(self):
        p=self.root/gate.DECISIONS
        p.write_bytes(p.read_bytes()+b" ")
        self.reject()
        self.seal()
        (self.root/"artifacts/S16-02.log").write_bytes(b"modified\n")
        self.reject()

    def test_missing_or_altered_criterion_receipt(self):
        p=self.root/self.decisions["criteria"][0]["path"]
        p.write_bytes(p.read_bytes()+b" ")
        self.reject()
        p.unlink()
        self.reject()

    def test_orphan_artifacts_and_unsigned_files(self):
        self.change_record(artifacts=["artifacts/S16-02.log"])
        self.reject()
        self.change_record(artifacts=["artifacts/S16-01.log"])
        (self.root/"extra").write_text("unlisted")
        self.reject()
        (self.root/"extra").unlink()
        (self.root/"unknown-dir").mkdir()
        self.reject()

    def test_duplicate_or_invalid_relative_paths(self):
        items=self.decisions["artifacts"]
        orig=items[0]
        for path in ("../../elsewhere","/tmp/escape","artifacts/../file",r"artifacts\absolute",items[1]["path"]):
            items[0]={**orig,"path":path}
            self.seal()
            self.reject()

    def test_fixed_criterion_paths_cannot_be_redirected(self):
        self.decisions["criteria"][0]["path"]=self.decisions["criteria"][1]["path"]
        self.seal()
        self.reject()

    def test_linked_directories_files_and_fifo_rejected(self):
        d=self.root/"artifacts"
        d.rename(self.root/"actual")
        d.symlink_to(self.root/"actual",target_is_directory=True)
        self.reject()
        d.unlink()
        (self.root/"actual").rename(d)
        p=d/"S16-01.log"
        p.unlink()
        p.symlink_to(self.pub)
        self.reject()
        p.unlink()
        os.link(self.pub,p)
        self.reject()
        p.unlink()
        os.mkfifo(p)
        self.reject()

    def test_duplicate_keys_in_json(self):
        data=b'{"ignored":"a","ignored":"b"}'
        (self.root/gate.DECISIONS).write_bytes(data)
        self.seal({"decisions_sha256":gate.sha(data)})
        (self.root/gate.DECISIONS).write_bytes(data)
        self.reject()


if __name__ == "__main__":
    unittest.main()

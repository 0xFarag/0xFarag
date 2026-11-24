# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Exercise the same API dispatcher used by the authenticated HTTP server."""
import base64
import copy
import json
import io
from zipfile import ZipFile, ZIP_DEFLATED
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from team.documents import RIGHTS, verify_archive, verify_document
from team.evidence import WorkflowError, handle, init_db, verify_package
from team.evidence_formats import canonical, parse_records, sha


def har(version="before", path="/objects/1", return_status=200):
    def exchange(route, status):
        return {"startedDateTime": version, "request":{"method":"GET","url":"https://example.test" + route,
                "headers":[{"name":"Cookie","value":"PRIVATE-SESSION"}]}, "response":{"status":status}}
    return canonical({"log":{"version":"1.2","entries":[exchange(path,return_status),exchange("/control",204)]}})


class CaseWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        init_db(self.db)
        case = self.api("POST",["cases"],{"title":"Local review","scope":"Own fixture","assets":["example.test"]})["case"]
        self.case = case["id"]
        self.original = self.upload(har())
        self.base = {"title":"Review access","asset":"example.test","expected":"access denied","observed":"access permitted",
                     "status":"confirmed","evidence_id":self.original["id"],"record":1,"control_evidence_id":self.original["id"],
                     "control_record":2,"control_expected":"control permitted","control_observed":"control permitted"}

    def api(self, method, parts, body=None, team="team1"):
        with self.db:
            return handle(self.db,team,"operator",method,parts,body or {},data_dir=self.temp.name)

    def upload(self,raw,fmt="har"):
        return self.api("POST",["cases",self.case,"imports"],{"format":fmt,"content_b64":base64.b64encode(raw).decode()})["import"]

    def add(self,route,obj):
        return self.api("POST",["cases",self.case,route],obj)[route]

    def test_six_passive_native_formats_and_structure(self):
        formats = {
            "burp": b'<issues><issue><name>Configured rule</name><host>https://example.test</host></issue></issues>',
            "har": har(),
            "nmap": b'<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports><port portid="443" protocol="tcp"><state state="open"/></port></ports></host></nmaprun>',
            "zap": canonical({"site":[{"alerts":[{"pluginid":"123","instances":[{"uri":"https://example.test/item"}]}]}]}),
            "openapi":canonical({"openapi":"3.1.0","info":{"title":"Example","version":"1"},"servers":[{"url":"https://example.test"}],"paths":{"/item":{"get":{}}}}),
            "nuclei":canonical({"type":"http","matcher-status":True,"template-id":"example","matched-at":"https://example.test/foo"})}
        for fmt,raw in formats.items():
            with self.subTest(fmt=fmt):
                item = self.upload(raw,fmt)
                self.assertTrue(item["records"])
                self.assertEqual(item["sha256"],sha(raw))
                self.assertEqual(item["id"],self.upload(raw,fmt)["id"])
                orig = self.api("GET",["cases",self.case,"imports",item["id"],"attachment"])
                self.assertEqual(base64.b64decode(orig["content_b64"]),raw)
                self.assertNotIn("PRIVATE-SESSION",json.dumps(item))
        for fmt,raw in [("nmap",b'<!DOCTYPE nmaprun SYSTEM "https://example.test"><nmaprun/>'),
                        ("burp",b'<!DOCTYPE issues [<!ENTITY x "expand">]><issues/>'),
                        ("har",b'{"log":{},"log":{}}'),("openapi",b'{}'),("nuclei",b'{"type":"file"}')]:
            with self.assertRaises(WorkflowError): self.upload(raw,fmt)

    def test_control_and_scope_gates(self):
        for changes in [{"asset":"outside.test"},{"control_record":1},{"control_observed":"failed"},{"observed":"access denied"}]:
            with self.subTest(changes=changes), self.assertRaises(WorkflowError):
                self.add("finding",dict(self.base,**changes))
        raw=canonical({"type":"http","matcher-status":True,"template-id":"label","matched-at":"https://example.test/"})
        imported=self.upload(raw,"nuclei")
        with self.assertRaises(WorkflowError):
            self.add("finding",dict(self.base,evidence_id=imported["id"]))
        hint=self.add("finding",dict(self.base,evidence_id=imported["id"],status="hint"))
        self.assertEqual(hint["status"],"hint")
        self.assertIsNone(hint["control"])

    def test_bound_retest_and_unchecked_coverage(self):
        original=self.add("finding",self.base)
        second=self.add("finding",dict(self.base,title="Unretested"))
        imported=self.upload(har("after",return_status=403))
        body={"finding_id":original["id"],"status":"fix_verified","observed":"access denied","evidence_id":imported["id"],"record":1,
              "control_evidence_id":imported["id"],"control_record":2,"control_expected":"control permitted","control_observed":"control permitted"}
        for changes in [{"evidence_id":self.original["id"]},{"observed":"unrelated"},
                        {"control_expected":"other","control_observed":"other"},{"control_record":1},
                        {"evidence_id":self.upload(har("other","/unrelated"))["id"]}]:
            with self.subTest(changes=changes), self.assertRaises(WorkflowError):
                self.add("retest",dict(body,**changes))
        test=self.add("retest",body)
        self.assertEqual(test["baseline_sha256"],original["finding_sha256"])
        for locale in ["de","en","fr","it","ar"]:
            package=self.api("POST",["cases",self.case,"handover"],{"language":locale})["package"]
            report=package["report"]
            self.assertEqual(report["counts"]["fix_verified"],1)
            self.assertEqual(report["counts"]["not_retested"],1)
            self.assertEqual(report["language"],locale)
            self.assertEqual(report["direction"],"rtl" if locale=="ar" else "ltr")
            appendix={f["id"]:f for f in report["appendix"]}
            self.assertIsNone(appendix[second["id"]]["retest_evidence"])
            self.assertEqual(appendix[original["id"]]["retest_evidence"]["sha256"],imported["sha256"])
            self.assertNotIn("PRIVATE-SESSION",json.dumps(package))
            self.assertNotIn("/objects/1",json.dumps(package))
        with self.assertRaises(WorkflowError):self.add("retest",dict(body,status="not_retested"))

    def test_team_isolation_and_signature_anchor(self):
        with self.assertRaises(WorkflowError):self.api("GET",["cases",self.case],team="unrelated")
        self.assertEqual(self.api("GET",["cases"],team="unrelated"),{"cases":[]})
        key=self.api("GET",["trust-key"])
        package=self.api("POST",["cases",self.case,"handover"],{"language":"en"})["package"]
        self.assertTrue(self.api("POST",["verify"],{"package":package})["valid"])
        self.assertFalse(self.api("POST",["verify"],{"package":package},team="unrelated")["valid"])
        for field in ("report","manifest","signature","extra"):
            altered=copy.deepcopy(package)
            if field in ("report","manifest"):
                altered[field]["tamper"]="yes"
            else:
                altered[field]="tampered"
            self.assertFalse(verify_package(altered,key)["valid"])
        self.assertFalse(verify_package(package,dict(key,fingerprint="f"*64))["valid"])
        root=Path(self.temp.name)
        (root/"package.json").write_bytes(canonical(package))
        (root/"public.json").write_bytes(canonical(key))
        run=subprocess.run([sys.executable,"-m","team.evidence","verify",str(root/"package.json"),"--trusted-key",str(root/"public.json")],capture_output=True,check=True)
        self.assertTrue(json.loads(run.stdout)["valid"])
        (root/"evidence-signing.key").unlink()
        with self.assertRaises(WorkflowError):self.api("GET",["trust-key"])

    def test_exact_document_bytes_are_bound_to_the_signed_handover(self):
        self.add("finding",self.base)
        key=self.api("GET",["trust-key"])
        wrong=copy.deepcopy(key)
        wrong["public_key"]=base64.b64encode(bytes(32)).decode()
        for fmt in ("html","pdf"):
            for lang in ("de","en","fr","it","ar"):
                with self.subTest(fmt=fmt,lang=lang):
                    result=self.api("POST",["cases",self.case,"handover"],{"language":lang,"format":fmt})
                    raw=base64.b64decode(result["archive_b64"],validate=True)
                    with ZipFile(io.BytesIO(raw)) as archive:
                        proof=json.loads(archive.read("proof.json"))
                        document=archive.read("report."+fmt)
                    self.assertTrue(document.startswith(b"%PDF" if fmt=="pdf" else b"<!doctype html>"))
                    self.assertEqual(proof["document"]["rights"],RIGHTS)
                    self.assertEqual(proof["document"]["case_id"],self.case)
                    self.assertEqual(proof["document"]["sha256"],sha(document))
                    self.assertEqual(proof["handover"]["report"]["rights"],RIGHTS)
                    self.assertNotIn(b"PRIVATE-SESSION",raw)
                    self.assertNotIn(b"/objects/1",raw)
                    checked=self.api("POST",["verify"],{"archive_b64":result["archive_b64"]})
                    self.assertTrue(checked["valid"])
                    self.assertEqual(checked["report"]["counts"]["not_retested"],1)
                    self.assertEqual(checked["report"]["language"],lang)
                    self.assertFalse(verify_document(proof,document+b"x",key)["valid"])
                    self.assertFalse(verify_document(proof,document,wrong)["valid"])
                    self.assertFalse(verify_document(proof,document,key,"unrelated")["valid"])
                    altered=copy.deepcopy(proof)
                    altered["handover"]["report"]["counts"]["fix_verified"]=3
                    self.assertFalse(verify_document(altered,document,key)["valid"])
                    altered=copy.deepcopy(proof)
                    altered["document"]["scope_sha256"]="f"*64
                    self.assertFalse(verify_document(altered,document,key)["valid"])
        # Also verify the files independently of the server or a session.
        root=Path(self.temp.name)
        for name,data in (("public.json",canonical(key)),("report.pdf",document),("proof.json",canonical(proof)),("delivery.zip",raw)):
            (root/name).write_bytes(data)
        cmd=[sys.executable,"-m","team.evidence","verify"]
        for args in ([str(root/"delivery.zip")],[str(root/"proof.json"),"--document",str(root/"report.pdf")]):
            output=subprocess.run(cmd+args+["--trusted-key",str(root/"public.json")],capture_output=True,check=True)
            self.assertTrue(json.loads(output.stdout)["valid"])

    def test_untrusted_archives_are_bounded_and_never_extracted(self):
        key=self.api("GET",["trust-key"])
        for names in (("../report.pdf","proof.json"),("proof.json","proof.json"),("proof.json","report.html","extra")):
            buffer=io.BytesIO()
            import warnings
            with warnings.catch_warnings(), ZipFile(buffer,"w") as archive:
                warnings.simplefilter("ignore",UserWarning)
                for name in names: archive.writestr(name,b"{}")
            self.assertFalse(verify_archive(buffer.getvalue(),key)["valid"])
        with ZipFile(buffer:=io.BytesIO(),"w",compression=ZIP_DEFLATED) as archive:
            archive.writestr("proof.json",b"{}")
            archive.writestr("report.pdf",b"A"*10000)
        self.assertFalse(verify_archive(buffer.getvalue(),key)["valid"])
        for value in (b"PK",b"X" * (3*1024*1024)):
            self.assertFalse(verify_archive(value,key)["valid"])
        with self.assertRaises(WorkflowError):
            self.api("POST",["cases",self.case,"handover"],{"format":"exe"})

    def test_retest_binding_includes_request_body_without_exposing_it(self):
        before=json.loads(har())
        entry=before["log"]["entries"][0]
        entry["request"].update(method="POST",postData={"mimeType":"text/plain","text":"private payload"})
        first=parse_records("har",canonical(before))[0]
        entry["request"]["postData"]["text"]="another body"
        later=parse_records("har",canonical(before))[0]
        self.assertNotEqual(first["request_key"],later["request_key"])
        self.assertNotIn("private payload",json.dumps(first))

    def test_original_source_and_claim_limitations(self):
        # An altered archive and a reprinted identical record cannot prove a retest.
        original=self.add("finding",self.base)
        reformatted=self.upload(har()+b" ")
        with self.assertRaises(WorkflowError):
            self.add("retest",{"finding_id":original["id"],"status":"inconclusive","evidence_id":reformatted["id"],"record":1,"observed":"unknown"})
        skipped=self.add("retest",{"finding_id":original["id"],"status":"not_retested"})
        self.assertIsNone(skipped["evidence"])
        self.assertEqual(parse_records("har",har())[0]["asset_id"],sha(b"example.test"))


if __name__ == "__main__":
    unittest.main()

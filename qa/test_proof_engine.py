# © Nasser Aldin Farag (0xFarag). All rights reserved.
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from team import proof_cli
from team.evidence_formats import canonical
from team.proof_engine import (DEPENDENCIES, compare, evaluate, import_source, lab_after_source,
                               lab_source, make_scope, record_retest, verify_semantics)
from team.proof_imports import safe_host, safe_path

CONTROLS = dict.fromkeys(DEPENDENCIES, True)
HOST = "example.test"


def row(id="b1", **changes):
    result = {"id": id, "source": "Burp", "host": HOST, "method": "GET", "path": "/invoices/1042",
              "status": 403, "marker": True, "rule": "protected-marker"}
    result.update(changes)
    return result


def burp(*items, absent=()):
    return import_source("burp", canonical({"observations": list(items), "observedAbsent": list(absent)}))


def evaluate_source(src, budget=12, controls=CONTROLS):
    return evaluate(make_scope([HOST], "Authorised offline evidence review", budget), [src], controls)


def add_run(report, selected, after, controls=CONTROLS):
    return record_retest(report, selected, after, controls)[0]


class Review(unittest.TestCase):
    def test_four_lab_observations_selection_preserves_root(self):
        scope = make_scope(["lab.authz.local"], "Synthetic lab", 7)
        r = evaluate(scope, [lab_source()], CONTROLS)
        original = r["evidenceRoot"]
        ids = [f["id"] for f in r["findings"]]
        self.assertEqual([f["status"] for f in r["findings"]], ["confirmed"]*4)
        self.assertEqual([f["observation"]["status"] for f in r["findings"]], [403]*4)
        self.assertEqual([f["status"] for f in r["retests"]], ["not_retested"]*4)
        add_run(r, ids[:3], lab_after_source())
        self.assertEqual([f["status"] for f in r["retests"]], ["resolved_check"]*3+["not_retested"])
        self.assertEqual(r["evidenceRoot"], original)
        self.assertEqual(r["spent"], 7)
        self.assertEqual(r["assurance"]["remaining"], 0)
        self.assertEqual(r["assurance"]["baselineSpent"], 4)
        self.assertTrue(verify_semantics(r))

    def test_all_five_verdicts_and_budget_order(self):
        src = burp(row("o", host="external.example"), row("m", marker=False), row("c"), row("i", status=None), row("b"))
        r = evaluate_source(src, budget=3)
        self.assertEqual([f["status"] for f in r["findings"]],
                         ["out_of_scope","no_marker","confirmed","inconclusive","budget_blocked"])
        self.assertEqual(r["spent"], 3)
        self.assertEqual(r["assurance"]["stopReason"], "budget_blocked")
        self.assertEqual([f["status"] for f in r["retests"]],
                         ["not_applicable","not_applicable","not_retested","not_applicable","not_applicable"])
        graph = r["graph"]
        node_ids = [n["id"] for layer in graph.values() for n in layer]
        self.assertEqual(len(node_ids),len(set(node_ids)))
        self.assertEqual(graph["result"][0]["relationshipId"],graph["relationship"][0]["id"])
        self.assertEqual(graph["relationship"][0]["intentId"],graph["intent"][0]["id"])

    def test_dependencies_and_minimal_reproducer(self):
        for revoked, blocked in (("token", {"token","identity","owner","denial"}), ("identity", {"identity","owner","denial"}),
                                 ("denial", {"denial"}), ("owner", {"owner"})):
            r = evaluate_source(burp(row()), controls={**CONTROLS,revoked:False})
            self.assertEqual({k for k,v in r["controls"].items() if not v["effective"]},blocked)
            self.assertEqual(r["findings"][0]["status"],"inconclusive")
        r = evaluate_source(burp(row()))
        reduced = r["findings"][0]["minimalReproducer"]
        self.assertEqual(len(reduced["observations"]),1)
        self.assertEqual(reduced["controls"],r["controls"])
        self.assertEqual(reduced["controls"]["owner"]["dependsOn"], ["identity"])

    def test_selected_without_evidence_and_non_selected_stay_honest(self):
        r = evaluate_source(burp(row(), row("no",marker=False)))
        add_run(r, ["b1","no"], None)
        self.assertEqual([x["status"] for x in r["retests"]],["inconclusive","not_applicable"])
        with self.assertRaises(ValueError):
            compare(r, ["b1", "b1"], None, CONTROLS)
        with self.assertRaises(ValueError):
            compare(r, ["unknown"], None, CONTROLS)
        self.assertTrue(verify_semantics(r))

    def test_wrong_contract_source_and_duplicates_fail_closed(self):
        r = evaluate_source(burp(row()))
        for changed in ({"rule":"other"}, {"host":"second.example"}, {"method":"HEAD"}, {"path":"/invoices/199"}):
            after = burp(row("z",marker=False,**changed),absent=["z"])
            self.assertEqual(compare(r,["b1"],after,CONTROLS)[0]["status"],"inconclusive")
        after_zap = import_source("ZAP",canonical({"observations":[row("z",source="ZAP",marker=False)],
                                                   "observedAbsent":["z"]}))
        self.assertEqual(compare(r,["b1"],after_zap,CONTROLS)[0]["status"],"inconclusive")
        after = burp(row("z",marker=False),row("z2",marker=False),absent=["z","z2"])
        self.assertEqual(compare(r,["b1"],after,CONTROLS)[0]["status"],"inconclusive")
        with self.assertRaises(ValueError):
            compare(r,["b1"],r["source"][0],CONTROLS)

    def test_real_transitions_restored_and_regression(self):
        r = evaluate_source(burp(row()))
        self.assertEqual(add_run(r,["b1"],burp(row("after1",status=503,marker=False)))["status"],"testability_lost")
        self.assertEqual(add_run(r,["b1"],burp(row("after2",marker=False),absent=["after2"]))["status"],"testability_restored")
        self.assertEqual(add_run(r,["b1"],burp(row("after3")))["status"],"regression")
        self.assertTrue(verify_semantics(r))

    def test_missing_marker_attestation_is_not_a_fix(self):
        r = evaluate_source(burp(row()))
        candidate = row("after1")
        candidate.pop("marker")
        item = add_run(r, ["b1"], burp(candidate))
        self.assertEqual(item["status"],"inconclusive")
        item = add_run(r, ["b1"], burp(row("after2",marker=False),absent=["after2"]))
        self.assertEqual(item["status"],"resolved_check")
        with self.assertRaises(ValueError):
            burp(row("r",marker=True),absent=["r"])

    def test_user_changing_serialization_does_not_create_fresh_evidence(self):
        src = burp(row())
        r = evaluate_source(src)
        different_bytes = import_source("burp", json.dumps([row()],indent=2).encode())
        self.assertEqual(compare(r,["b1"],different_bytes,CONTROLS)[0]["reason"],"fresh_evidence_required")
        after = burp(row("after0", marker=False),absent=["after0"])
        self.assertEqual(add_run(r,["b1"],after)["status"],"resolved_check")
        reformatted = import_source("burp", json.dumps({"observations":after["observations"],
                                                        "observedAbsent":["after0"]},indent=2).encode())
        self.assertEqual(add_run(r,["b1"],reformatted)["reason"],"fresh_evidence_required")

    def test_retests_share_original_budget(self):
        r = evaluate_source(burp(row()), budget=2)
        add_run(r,["b1"],burp(row("a",marker=False),absent=["a"]))
        self.assertEqual(add_run(r,["b1"],burp(row("b")))["reason"],"budget_blocked")
        self.assertTrue(verify_semantics(r))

    def test_replay_detects_projection_changes(self):
        r = evaluate_source(burp(row()))
        add_run(r,["b1"],burp(row("a",marker=False),absent=["a"]))
        for where, alteration in (
                (["spent"],9),(["assurance","remaining"],999),(["controls","identity","effective"],False),
                (["findings",0,"status"],"out_of_scope"),(["findings",0,"minimalReproducer","controls"],{}),
                (["retestRuns",0,"results",0,"reason"],"made_up"),(["retests",0,"status"],"testability_lost"),
                (["retestRuns",0,"selected"],[]),(["evidenceRoot"],"a"*64),(["contractRoot"],"a"*64)):
            other = copy.deepcopy(r)
            target = other
            for part in where[:-1]:
                target = target[part]
            target[where[-1]] = alteration
            with self.subTest(where=where), self.assertRaises(ValueError):
                verify_semantics(other)

    def test_invalid_inputs_and_lab_separation(self):
        for args in (([HOST,HOST],"scope",4),([HOST],"scope",True),([HOST],"scope",-1),([],"scope",5)):
            with self.assertRaises(ValueError):
                make_scope(*args)
        with self.assertRaises(ValueError):
            evaluate_source(burp(row()),controls={**CONTROLS,"token":1})
        with self.assertRaises(ValueError):
            evaluate(make_scope([HOST],"authorised",4),[lab_source(),burp(row())],CONTROLS)
        r = evaluate_source(burp(row()))
        with self.assertRaises(ValueError):
            compare(r,["b1"],lab_after_source(),CONTROLS)

    def test_common_credentials_are_rejected_in_review_text_and_labels(self):
        for value in ("Authorization: Bearer private", "cookie: test=value", "client_secret=example"):
            with self.assertRaises(ValueError):
                make_scope([HOST], value, 12)
        for value in ("ghp_" + "a"*35, "eyJhbGci.eyJpc3M.fakeSignature"):
            with self.assertRaises(ValueError):
                burp(row(rule=value))

    def test_cli_same_results(self):
        with tempfile.TemporaryDirectory() as td:
            files = [Path(td)/name for name in ("scope","ctrl","obs","report")]
            scope = make_scope([HOST],"Authorised offline evidence review",12)
            for path,data in zip(files, (scope,CONTROLS,[row()])):
                path.write_bytes(canonical(data))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(proof_cli.main(["assess","--scope",str(files[0]),"--controls",str(files[1]),
                                                "--source","burp",str(files[2])]),0)
            report = json.loads(out.getvalue())
            self.assertEqual(report, evaluate(scope, [import_source("burp",files[2].read_bytes())],CONTROLS))
            files[3].write_bytes(canonical(report))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(proof_cli.main(["verify-semantics",str(files[3])]),0)
            after = Path(td)/"after.json"
            after.write_bytes(canonical({"observations":[row("after",marker=False)],"observedAbsent":["after"]}))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                proof_cli.main(["retest","--report",str(files[3]),"--controls",str(files[1]),"--select","b1",
                                "--after","burp",str(after)])
            appended = json.loads(out.getvalue())
            self.assertTrue(verify_semantics(appended))
            self.assertEqual(appended["retests"][0]["status"], "resolved_check")
            self.assertEqual(json.loads(files[3].read_bytes()),report)



class Formats(unittest.TestCase):
    def test_native_burp_doctype_is_stripped_and_must_match_the_document(self):
        native = (Path(__file__).parent / "fixtures/burp.xml").read_bytes()
        parsed = import_source("burp", native)
        observation, = parsed["observations"]
        self.assertEqual(observation["host"], "app.example")
        self.assertFalse(observation["marker"])
        self.assertNotIn(b"PRIVATE_PAYLOAD", canonical(parsed))
        history = (b'<!DOCTYPE items [<!ELEMENT items (item*)><!ATTLIST items burpVersion CDATA "">]>'
                   b'<items><item><url>https://app.example/orders</url><method>GET</method>'
                   b'<status>200</status></item></items>')
        self.assertEqual(import_source("burp", history)["observations"][0]["status"], 200)
        for declaration in (b'<!DOCTYPE nmaprun>', b'<!DOCTYPE issues>', b'<!DOCTYPE items SYSTEM "report.dtd">',
                            b'<!DOCTYPE items [<!ENTITY external SYSTEM "report.dtd">]>',
                            b'<!DOCTYPE items [<!ELEMENT items (%external;)>]>'):
            with self.subTest(declaration=declaration), self.assertRaises(ValueError):
                import_source("burp", declaration + history.split(b"]>", 1)[1])

    def test_native_formats_are_passive(self):
        samples = {
            "burp": b"<items><item><url>https://example.test/invoices/1042</url><method>GET</method><status>403</status></item></items>",
            "zap": canonical({"site":[{"alerts":[{"pluginid":"100","instances":[{"uri":"https://example.test/invoices/1042","method":"GET"}]}]}]}),
            "openapi": canonical({"openapi":"3.1.0","info":{"title":"svc"},"servers":[{"url":"https://example.test/api"}],
                                  "paths":{"/invoices/{n}":{"get":{}}}}),
            "har": canonical({"log":{"version":"1.2","entries":[{"request":{"url":"https://example.test/invoices/1042","method":"GET"},"response":{"status":403}}]}}),
            "nuclei": b'{"type":"http","matcher-status":true,"template-id":"internal-rule","matched-at":"https://example.test/invoices/1042"}\n',
            "nmap": b'<!DOCTYPE nmaprun><nmaprun><host><address addrtype="ipv4" addr="192.0.2.1"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>'}
        with patch("socket.socket",side_effect=AssertionError("unexpected network access")):
            for fmt,raw in samples.items():
                with self.subTest(fmt=fmt):
                    src = import_source(fmt,raw)
                    self.assertEqual(len(src["observations"]),1)
                    self.assertFalse(src["observations"][0]["marker"])
                    self.assertNotEqual(evaluate_source(src)["findings"][0]["status"],"confirmed")

    def test_invalid_documents_rejected(self):
        for fmt,raw in (("burp",b'<!DOCTYPE items><items></items>'),("burp",b'<!DOCTYPE x [<!ENTITY e "s">]><items></items>'),
                        ("zap",b'{"site":[]}'),("burp",b'{"observations":[],"observations":[]}'),
                        ("har",b'{"log":{"version":"1.2","entries":[{"request":{}}]}}'),
                        ("burp",canonical([row("r"),row("r")])),("burp",canonical([row(marker=1)])),
                        ("burp",canonical([row(cookie="hi")])),("burp",canonical([row(status=0)])),
                        ("burp",canonical([row(source="Lab")])),("unknown",b'{}'),("nmap",b"x"*(1024*1024+1))):
            with self.subTest(fmt=fmt), self.assertRaises(ValueError):
                import_source(fmt,raw)

    def test_path_safety_private_fields_are_removed(self):
        reason = "PRIVATE-SESSION"
        inp = {"log":{"version":"1.2","entries":[{"request":{"url":"https://example.test/session/"+reason+"?pass="+reason,
            "method":"GET","headers":[{"name":"Authorization","value":reason}],"postData":{"text":reason}},
            "response":{"status":403,"cookies":[{"value":reason}],"content":{"text":reason}}}]}}
        src = import_source("har",canonical(inp))
        self.assertNotIn(reason,canonical(src).decode())
        path = src["observations"][0]["path"]
        self.assertRegex(path, r"^/session/redacted-[a-f0-9]{24}$")
        self.assertEqual(safe_path(path),path)
        self.assertEqual(safe_path("/invoices/1042?session=secret#other"),"/invoices/1042")
        for invalid in ("/a/%2f","/../a","/a/%252f","https://example.test/","//evil.test/a"):
            with self.assertRaises(ValueError):
                safe_path(invalid)
        with self.assertRaises(ValueError):
            safe_host("fe80::1%secret")


if __name__ == "__main__":
    unittest.main()

"""Rendered safety, trust wording, control distinctions and CI semantics."""

from html.parser import HTMLParser
import unittest
import xml.etree.ElementTree as ET

from authzledger.evidence import compare_reports, seal_report
from authzledger.reports import render_diff_html, render_html, render_junit


def make_report(outcomes=("pass", "fail", "error", "inconclusive")):
    results = [
        {
            "id": f"case-{index}", "identity": "owner", "method": "GET", "path": "/invoice/1",
            "outcome": outcome, "status": 200 if outcome in ("pass", "fail") else None,
            "duration_ms": 10.0,
            "checks": [{"type": "status", "passed": outcome == "pass"}] if outcome in ("pass", "fail") else [],
            "reason": "Configured outcome.", "response_sha256": "a" * 64,
            "control_type": "positive" if index == 0 else "negative", "requires": [] if index == 0 else ["case-0"],
        }
        for index, outcome in enumerate(outcomes)
    ]
    return {
        "schema_version": 1, "tool": {"name": "AuthzLedger", "version": "0.1.0"},
        "name": "Local fixture", "target": "http://127.0.0.1:8765", "contract_sha256": "b" * 64,
        "started_at": "2026-10-08T00:00:00Z", "finished_at": "2026-10-08T00:00:01Z",
        "summary": {**{outcome: sum(r["outcome"] == outcome for r in results)
                        for outcome in ("pass", "fail", "error", "inconclusive")},
                    "total": len(results)}, "results": results,
    }


class TagCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)


class HtmlTests(unittest.TestCase):
    def test_self_contained_responsive_report_and_scope(self):
        rendered = render_html(seal_report(make_report()))
        parser = TagCollector()
        parser.feed(rendered)
        self.assertNotIn("script", parser.tags)
        self.assertNotIn("link", parser.tags)
        self.assertNotIn("iframe", parser.tags)
        self.assertIn("Configured checks", rendered)
        self.assertIn("4 configured cases", rendered)
        self.assertIn("Positive control", rendered)
        self.assertIn("Negative control", rendered)
        self.assertIn("Required controls: case-0", rendered)
        self.assertIn("not a signature or independent proof of authenticity", rendered)
        self.assertIn("never a pass", rendered)
        self.assertIn("grid-template-columns:minmax(0,1.618fr)", rendered)
        self.assertIn("#071722", rendered)
        self.assertIn("#43D6CF", rendered)
        self.assertIn("#C8A66B", rendered)

    def test_every_displayed_untrusted_string_is_escaped(self):
        payload = '</title><script>alert("x")</script><img src=x onerror="alert(1)">&\''
        report = make_report(("pass",))
        report.update({"name": payload, "target": payload, "started_at": payload, "finished_at": payload})
        result = report["results"][0]
        for key in ("id", "identity", "method", "path", "reason"):
            result[key] = payload
        result["checks"][0]["type"] = payload
        result["requires"] = [payload]
        rendered = render_html(seal_report(report))
        parser = TagCollector()
        parser.feed(rendered)
        self.assertNotIn(payload, rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("script", parser.tags)
        self.assertEqual(parser.tags.count("img"), 1)  # The bundled, trusted brand asset only.
        sources = [value for key, value in parser.attributes if key == "src"]
        self.assertEqual(len(sources), 1)
        self.assertTrue(sources[0].startswith("data:image/png;base64,"))
        self.assertFalse(any(key.lower().startswith("on") for key, _ in parser.attributes))
        self.assertEqual(parser.tags.count("title"), 1)

    def test_control_type_cannot_inject_class_or_markup(self):
        report = make_report(("pass",))
        report["results"][0]["control_type"] = '<script>control()</script>'
        rendered = render_html(seal_report(report))
        self.assertNotIn("control()", rendered)
        self.assertIn("Configured case", rendered)

    def test_inconclusive_is_not_success(self):
        rendered = render_html(seal_report(make_report(("inconclusive",))))
        self.assertIn("Inconclusive cases require follow-up", rendered)
        self.assertNotIn("All configured cases passed", rendered)
        self.assertIn('class="badge inconclusive"', rendered)

    def test_empty_report_does_not_claim_success(self):
        rendered = render_html(seal_report(make_report(())))
        self.assertIn("No configured cases recorded", rendered)
        self.assertNotIn("All configured cases passed", rendered)

    def test_modified_metadata_shows_integrity_failure(self):
        report = seal_report(make_report())
        report["name"] = "Modified title"
        rendered = render_html(report)
        self.assertIn("Integrity verification failed", rendered)
        self.assertNotIn("Local hash chain consistent", rendered)

    def test_non_rendered_extra_fields_do_not_leak(self):
        report = make_report(("pass",))
        report["results"][0]["unexpected_response_body"] = "DO_NOT_RENDER_RESPONSE_CONTENT"
        report["results"][0]["unexpected_header"] = "DO_NOT_RENDER_AUTH_TOKEN"
        sealed = seal_report(report)
        for rendered in (render_html(sealed), render_junit(sealed)):
            self.assertNotIn("DO_NOT_RENDER", rendered)


class JunitTests(unittest.TestCase):
    def test_outcomes_have_distinct_ci_meaning(self):
        rendered = render_junit(seal_report(make_report()))
        suite = ET.fromstring(rendered)
        self.assertEqual(suite.tag, "testsuite")
        self.assertEqual(suite.attrib["tests"], "4")
        self.assertEqual(suite.attrib["failures"], "1")
        self.assertEqual(suite.attrib["errors"], "1")
        self.assertEqual(suite.attrib["skipped"], "1")
        self.assertEqual(suite.attrib["time"], "0.040")
        cases = suite.findall("testcase")
        self.assertEqual(len(cases), 4)
        self.assertEqual(len(cases[0]), 0)
        self.assertIsNotNone(cases[1].find("failure"))
        self.assertIsNotNone(cases[2].find("error"))
        self.assertIsNotNone(cases[3].find("skipped"))
        self.assertIn("independent authenticity", rendered)

    def test_xml_injection_is_data_and_illegal_controls_are_replaced(self):
        payload = '\"/><evil attr="x">&bad</evil>\x00\x01'
        report = make_report(("fail",))
        report["name"] = payload
        report["results"][0].update({"id": payload, "identity": payload, "reason": payload})
        rendered = render_junit(seal_report(report))
        suite = ET.fromstring(rendered)
        self.assertEqual(suite.attrib["name"], payload.replace("\x00", "�").replace("\x01", "�"))
        self.assertEqual(suite.findall(".//evil"), [])
        self.assertEqual(len(suite.findall("testcase")), 1)
        self.assertNotIn("\x00", rendered)
        self.assertNotIn("\x01", rendered)

    def test_tampered_junit_is_refused(self):
        report = seal_report(make_report())
        report["target"] = "http://wrong-target.invalid"
        with self.assertRaisesRegex(ValueError, "invalid evidence"):
            render_junit(report)

    def test_empty_junit_is_valid_and_has_zero_cases(self):
        suite = ET.fromstring(render_junit(seal_report(make_report(()))))
        self.assertEqual(suite.attrib["tests"], "0")
        self.assertEqual(suite.attrib["time"], "0.000")


class DiffHtmlTests(unittest.TestCase):
    def test_changed_cases_and_inconclusive_semantics_are_clear(self):
        old = seal_report(make_report(("pass", "fail", "inconclusive")))
        new = seal_report(make_report(("fail", "pass", "pass")))
        rendered = render_diff_html(compare_reports(old, new))
        self.assertIn("Outcome transitions", rendered)
        self.assertIn("case-0", rendered)
        self.assertIn("case-1", rendered)
        self.assertIn("case-2", rendered)
        self.assertIn("Inconclusive transition", rendered)
        self.assertIn("This does not establish resolution", rendered)
        self.assertIn("not independent proof of authenticity", rendered)

    def test_diff_untrusted_metadata_ids_and_labels_are_escaped(self):
        payload = '<script>alert("diff")</script>'
        report = make_report(("pass",))
        report.update({"name": payload, "target": payload})
        report["results"][0]["id"] = payload
        sealed = seal_report(report)
        diff = compare_reports(sealed, sealed)
        diff["transitions"][0]["category"] = payload
        diff["transitions"][0]["baseline"] = payload
        rendered = render_diff_html(diff)
        parser = TagCollector()
        parser.feed(rendered)
        self.assertNotIn("script", parser.tags)
        self.assertNotIn(payload, rendered)
        self.assertIn("&lt;script&gt;", rendered)


if __name__ == "__main__":
    unittest.main()

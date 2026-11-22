"""contracts/threats/review-findings.json is traceability for the second security review's twelve findings (T-1 of the 2026-11-14 findings plan). A finding is 'fixed'
only if every test it names exists as a Go test function; an 'open' finding names no test and either an owner story or none (undecided). No finding is forgotten."""
import json
import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
DATA = json.loads((ROOT / "contracts" / "threats" / "review-findings.json").read_text())


class ReviewFindings(unittest.TestCase):
    def test_all_twelve_are_listed_once_and_in_order(self):
        self.assertEqual([f["id"] for f in DATA["findings"]], ["F-%02d" % i for i in range(1, 13)])

    def test_each_entry_has_exactly_the_agreed_fields_and_values(self):
        for f in DATA["findings"]:
            self.assertEqual(set(f), {"id", "title", "severity", "status", "tests", "story"}, f["id"])
            self.assertIn(f["severity"], ("low", "medium", "high"), f["id"])
            self.assertIn(f["status"], ("fixed", "open"), f["id"])
            self.assertTrue(f["story"] is None or re.fullmatch(r"M\d+-E\d{2}-S\d{2}", f["story"]), f["id"])

    def test_a_fixed_finding_names_tests_that_exist_and_an_open_one_names_none(self):
        for f in DATA["findings"]:
            if f["status"] == "open":
                self.assertEqual(f["tests"], [], f["id"])
                continue
            self.assertTrue(f["tests"], "%s is fixed but names no test" % f["id"])
            for ref in f["tests"]:
                path, _, name = ref.partition("::")
                self.assertTrue(path.startswith("backend/") and path.endswith("_test.go"), ref)
                body = (ROOT / path).read_text()
                self.assertTrue(re.search(r"(?m)^func %s\(t \*testing\.T\)" % re.escape(name), body), "%s is not a Go test function" % ref)

    def test_no_secret_looking_text(self):
        text = json.dumps(DATA)
        self.assertNotRegex(text, r"(?i)password\s*[:=]|BEGIN [A-Z ]*PRIVATE KEY|\b\d{1,3}(\.\d{1,3}){3}\b")


if __name__ == "__main__":
    unittest.main()

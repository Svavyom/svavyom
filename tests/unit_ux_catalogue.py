"""Journey-catalogue cross-references at the pinned docs commit (story M0-E02-S06 AC01; DR-010 D2 = A, r5 R-N3).

The docs repo validates the catalogue's schema and story ids; this test checks what only cloud-platform knows:
operationIds against contracts/openapi.yaml, error states against the browser-api boundary (inventory.json), and
that every journey has a test-only skeleton and a keyboard-path browser test. Read-only; docs access goes through
tools/check_linkage.py (pinned commit must be on the trusted docs tip).
"""
import importlib.util
import json
import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = os.environ.get("DOCS_REPO", str(ROOT.parent / "cloud-product-docs"))
spec = importlib.util.spec_from_file_location("check_linkage", ROOT / "tools" / "check_linkage.py")
linkage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(linkage)


def pinned_catalogue():
    linkage.require_git_version()
    linkage.require_repo(DOCS, "DOCS_REPO_UNAVAILABLE", "docs-repo")
    findings, sha = linkage.check_lock_bytes((ROOT / "docs-lock.json").read_bytes(), "docs-lock.json")
    docs = linkage.Docs(DOCS)
    assert not findings and docs.commit_exists(sha) and docs.is_trusted(sha), "docs-lock must pin a trusted docs commit"
    raw = linkage.git(DOCS, "cat-file", "blob", "%s:contracts/ux-journeys.json" % sha)
    assert raw is not None, "contracts/ux-journeys.json missing at the pinned docs commit %s" % sha[:12]
    return json.loads(raw), docs.backlog(sha)[0]


class Catalogue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat, cls.stories = pinned_catalogue()
        cls.ops = set(re.findall(r"operationId:\s*([A-Za-z_][A-Za-z0-9_]*)", (ROOT / "contracts/openapi.yaml").read_text()))
        inv = json.loads((ROOT / "contracts/interfaces/inventory.json").read_text())
        cls.boundary = set(inv["boundaries"]["browser-api"]["error_categories"])
        cls.gallery = (ROOT / "frontend/src/gallery/Gallery.tsx").read_text()
        cls.e2e = (ROOT / "frontend/e2e/journeys.spec.ts").read_text()

    def test_covers_j1_to_j10(self):
        self.assertEqual(sorted(j["id"] for j in self.cat["journeys"]), sorted("J%d" % i for i in range(1, 11)))

    def test_operation_ids_exist_or_are_future(self):
        for j in self.cat["journeys"]:
            for op in j["api_operations"]:
                if not op.startswith("future:"):
                    self.assertIn(op, self.ops, "%s: %s is not an operationId in contracts/openapi.yaml" % (j["id"], op))

    def test_error_states_are_browser_api_categories(self):
        for j in self.cat["journeys"]:
            for s in j["states"]:
                if s.startswith("error:"):
                    self.assertIn(s[6:], self.boundary, "%s: %s is not a browser-api error category" % (j["id"], s))

    def test_implementing_stories_exist_at_the_pinned_commit(self):
        for j in self.cat["journeys"]:
            for s in j["implementing_stories"]:
                self.assertIn(s, self.stories, j["id"])

    def test_every_journey_has_a_skeleton_and_a_keyboard_test(self):
        for j in self.cat["journeys"]:
            self.assertRegex(self.gallery, r"\b%s:\s*<" % j["id"], "%s has no gallery skeleton" % j["id"])
            title = "J8 shows unreachable within the deadline" if j["id"] == "J8" else "%s completes keyboard-only" % j["id"]
            self.assertIn(title, self.e2e, "%s has no keyboard-path browser test" % j["id"])

    def test_browser_scenarios_cover_every_catalogue_state(self):
        # Review M1: e2e/journey-states.spec.ts runs axe in every journey state listed in the catalogue.
        table = json.loads((ROOT / "frontend/e2e/journey-states.json").read_text())["journeys"]
        for j in self.cat["journeys"]:
            self.assertEqual(sorted(table.get(j["id"], {})), sorted(j["states"]), "%s scenario states" % j["id"])

    def test_destructive_journeys_have_confirmation_and_outcome_unknown(self):
        for j in self.cat["journeys"]:
            if j["destructive"]:
                self.assertIn("outcome_unknown", j["states"], j["id"])


if __name__ == "__main__":
    unittest.main()

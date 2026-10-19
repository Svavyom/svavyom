"""Tests of the open-core boundary check (tools/check_open_core.py)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import check_open_core as oc  # noqa: E402

CFG = {"schema": 1, "tiers": {"core": ["backend/**", "release/**"], "interface": ["contracts/**"], "docs": ["docs/**", "REUSE.toml"], "internal": ["tests/**"]},
       "forbidden_import_prefixes": ["example.invalid/dedicatedcloud/premium", "svavyom-premium"],
       "forbidden_tokens": ["license_key", "entitlement", "trial_expires", "max_hosts", "phone_home"],
       "scanned_source": ["backend/**/*.go", "backend/go.mod"], "token_exceptions": ["backend/**/*_test.go"],
       "copyright": "2026 Test", "tier_licence": {"core": "AGPL-3.0-or-later", "interface": "Apache-2.0", "docs": "Apache-2.0", "internal": "AGPL-3.0-or-later"}}


def repo(files, cfg=CFG, reuse=True):
    d = tempfile.mkdtemp()
    extra = {"REUSE.toml": oc.expected_reuse(cfg)} if reuse else {}
    for rel, text in {"release/open-core.json": json.dumps(cfg), **extra, **files}.items():
        p = Path(d) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    return d


class OpenCore(unittest.TestCase):
    def codes(self, files, cfg=CFG, reuse=True):
        return sorted({f[0] for f in oc.check(repo(files, cfg, reuse))})

    def test_clean_tree_passes(self):
        self.assertEqual(self.codes({"backend/a.go": "package a\n", "docs/x.md": "x", "tests/t.py": "x"}), [])

    def test_the_licence_map_must_match_the_tiers(self):
        self.assertEqual(self.codes({"backend/a.go": "x"}, reuse=False), ["OPEN_CORE_LICENCE_MAP"])
        exp = oc.expected_reuse(CFG)
        self.assertIn('SPDX-License-Identifier = "AGPL-3.0-or-later"', exp)
        self.assertIn('SPDX-FileCopyrightText = "2026 Test"', exp)
        self.assertIn('path = ["contracts/**"]', exp)

    def test_a_file_in_no_tier_fails(self):
        self.assertEqual(self.codes({"surprise/new.txt": "x"}), ["OPEN_CORE_UNCLASSIFIED"])

    def test_a_file_in_two_tiers_fails(self):
        self.assertEqual(self.codes({"backend/a.go": "x"}, dict(CFG, tiers=dict(CFG["tiers"], docs=["backend/**", "REUSE.toml"]))), ["OPEN_CORE_AMBIGUOUS"])

    def test_importing_a_premium_package_fails(self):
        self.assertEqual(self.codes({"backend/a.go": 'import "example.invalid/dedicatedcloud/premium/hub"\n'}), ["OPEN_CORE_PREMIUM_IMPORT"])
        self.assertEqual(self.codes({"backend/go.mod": "require svavyom-premium v1.0.0\n"}), ["OPEN_CORE_PREMIUM_IMPORT"])

    def test_licence_trial_entitlement_and_host_limit_logic_fails(self):
        for tok in ("licenseKey := os.Getenv(\"LICENSE_KEY\")", "if entitlement.Valid() {", "trial_expires = now", "const MAX_HOSTS = 2", "phone_home()"):
            self.assertEqual(self.codes({"backend/a.go": "package a\n" + tok + "\n"}), ["OPEN_CORE_GATING_TOKEN"], tok)

    def test_tests_may_mention_the_tokens_and_unscanned_files_are_not_read(self):
        self.assertEqual(self.codes({"backend/a_test.go": "// a test that asserts there is no entitlement logic\n", "docs/x.md": "entitlement", "tests/t.py": "license_key"}), [])


if __name__ == "__main__":
    unittest.main()

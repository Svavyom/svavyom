"""Tests for tools/check_ci_policy.py (story M0-E02-S02 AC03, tier T0)."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools" / "check_ci_policy.py"
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
PINS = "| Action | Commit SHA |\n|---|---|\n| actions/checkout | %s |\n" % SHA

GOOD = """name: ok
on:
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@%s # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - run: make check
""" % SHA


def run(workflow, pins=PINS):
    with tempfile.TemporaryDirectory() as tmp:
        wf = Path(tmp) / "wf.yml"
        wf.write_text(workflow)
        pin_file = Path(tmp) / "pins.md"
        pin_file.write_text(pins)
        proc = subprocess.run([sys.executable, str(CHECKER), "--pins", str(pin_file), str(wf)],
                              capture_output=True, text=True, timeout=30)
        return proc.returncode, proc.stdout


class CiPolicy(unittest.TestCase):
    def assertViolation(self, workflow, fragment, pins=PINS):
        code, out = run(workflow, pins)
        self.assertEqual(code, 1, out)
        self.assertIn(fragment, out)

    def test_compliant_fixture_passes(self):
        self.assertEqual(run(GOOD), (0, "OK ci-policy: 1 workflow(s) compliant\n"))

    def test_committed_workflows_pass(self):
        proc = subprocess.run([sys.executable, str(CHECKER), "--pins", str(ROOT / "docs/CI-PINS.md"),
                               str(ROOT / ".github/workflows")], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_tag_reference_rejected(self):
        self.assertViolation(GOOD.replace("@" + SHA, "@v7"), "not pinned to a full commit SHA")

    def test_short_sha_rejected(self):
        self.assertViolation(GOOD.replace("@" + SHA, "@" + SHA[:12]), "not pinned to a full commit SHA")

    def test_unlisted_sha_rejected(self):
        self.assertViolation(GOOD.replace(SHA, "a" * 40), "not recorded in CI-PINS.md")

    def test_unlisted_action_rejected(self):
        wf = GOOD.replace("      - run: make check", "      - uses: evil/action@%s\n      - run: make check" % SHA)
        self.assertViolation(wf, "evil/action@%s is not recorded" % SHA)

    def test_docker_and_local_actions_rejected(self):
        self.assertViolation(GOOD.replace("      - run: make check", "      - uses: docker://alpine:3"), "only pinned remote")
        self.assertViolation(GOOD.replace("      - run: make check", "      - uses: ./local"), "only pinned remote")

    def test_write_permissions_rejected(self):
        self.assertViolation(GOOD.replace("  contents: read", "  contents: write"), "exactly 'contents: read'")
        self.assertViolation(GOOD.replace("  contents: read", "  contents: read\n  packages: write"), "exactly 'contents: read'")
        self.assertViolation(GOOD.replace("permissions:\n  contents: read", "permissions: write-all"), "exactly 'contents: read'")

    def test_missing_permissions_rejected(self):
        self.assertViolation(GOOD.replace("permissions:\n  contents: read\n", ""), "exactly 'contents: read'")

    def test_job_write_permission_rejected(self):
        wf = GOOD.replace("    timeout-minutes: 10", "    timeout-minutes: 10\n    permissions:\n      contents: write")
        self.assertViolation(wf, "requests write or broad permissions")

    def test_pull_request_target_rejected(self):
        self.assertViolation(GOOD.replace("  pull_request:", "  pull_request_target:"), "pull_request_target")

    def test_secrets_rejected(self):
        wf = GOOD.replace("      - run: make check", "      - run: echo ${{ secrets.TOKEN }}")
        self.assertViolation(wf, "secrets references are forbidden")
        wf = GOOD.replace("      - run: make check", "      - run: echo ${{ secrets['TOKEN'] }}")
        self.assertViolation(wf, "secrets references are forbidden")
        wf = GOOD.replace("      - run: make check", "      - env:\n          X: ${{ toJSON(secrets) }}\n        run: true")
        self.assertViolation(wf, "secrets references are forbidden")

    def test_persist_credentials_required(self):
        self.assertViolation(GOOD.replace("          persist-credentials: false\n", ""), "persist-credentials: false")
        self.assertViolation(GOOD.replace("persist-credentials: false", "persist-credentials: true"),
                             "persist-credentials: false")

    def test_persist_credentials_of_other_step_does_not_count(self):
        wf = GOOD.replace("          persist-credentials: false\n", "") + \
            "      - uses: actions/checkout@%s\n        with:\n          persist-credentials: false\n" % SHA
        self.assertViolation(wf, "checkout lacks with.persist-credentials: false")

    def test_timeout_required(self):
        self.assertViolation(GOOD.replace("    timeout-minutes: 10\n", ""), "lacks a numeric timeout-minutes")
        self.assertViolation(GOOD.replace("timeout-minutes: 10", "timeout-minutes: ${{ 600 }}"),
                             "lacks a numeric timeout-minutes")

    def test_second_job_without_timeout_rejected(self):
        wf = GOOD + "  other:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n"
        self.assertViolation(wf, "job other lacks a numeric timeout-minutes")

    def test_yaml_constructs_rejected(self):
        self.assertViolation(GOOD + "---\nname: two\n", "multi-document")
        self.assertViolation(GOOD.replace("    runs-on: ubuntu-24.04", "    runs-on: &r ubuntu-24.04"), "anchors")
        self.assertViolation(GOOD.replace("    runs-on", "\truns-on"), "tab characters")

    def test_usage_errors(self):
        proc = subprocess.run([sys.executable, str(CHECKER), "--pins", "/nonexistent", "x"],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run([sys.executable, str(CHECKER), "--pins", str(ROOT / "docs/CI-PINS.md"), tmp],
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 1, proc.stdout)


class CorpusRegressions(unittest.TestCase):
    """Every reviewer bypass workflow from all review cycles stays rejected."""

    def test_bypass_fixtures_rejected(self):
        files = sorted((ROOT / "tests/fixtures/ci-policy/bypass").glob("*.yml"))
        self.assertGreaterEqual(len(files), 69)
        for wf in files:
            with self.subTest(fixture=wf.name):
                code, out = run(wf.read_text())
                self.assertEqual(code, 1, "%s passed:\n%s" % (wf.name, out))

    def test_compliant_fixtures_accepted(self):
        # Rejected by the former hand-written subset parser, but compliant when
        # read by a real YAML parser (confirmed against go-yaml v3).
        for wf in sorted((ROOT / "tests/fixtures/ci-policy/compliant").glob("*.yml")):
            with self.subTest(fixture=wf.name):
                self.assertEqual(run(wf.read_text())[0], 0)


class ExploitRegressions(unittest.TestCase):
    """Named exploits from S02 reviews, asserted on policy outcome (parser-independent)."""

    def assertRejected(self, workflow, fragment):
        code, out = run(workflow)
        self.assertEqual(code, 1, out)
        self.assertIn(fragment, out)

    def test_cycle1_flow_and_quoted_forms(self):
        self.assertRejected(GOOD.replace("      - run: make check", "      - {uses: evil/act@main}"), "not pinned")
        self.assertRejected(GOOD.replace("      - run: make check", '      - "uses": evil/act@main'), "not pinned")
        self.assertRejected(GOOD.replace("permissions:\n  contents: read", "permissions: {contents: write}"),
                            "exactly 'contents: read'")
        self.assertRejected(GOOD + "permissions:\n  contents: write\n", "duplicate key")

    def test_n1_escaped_quote(self):
        # Real YAML: the escaped quote keeps "permissions" inside the name string.
        wf = 'name: "t\\" #\npermissions:\n  contents: read\nrun-name: x # "\n' + GOOD.split("permissions:\n  contents: read\n")[1]
        code, out = run("on:\n  pull_request:\n" + wf)
        self.assertEqual(code, 1, out)

    def test_n9_secrets_in_block_scalars(self):
        for header in ("|", ">-", "|+"):
            wf = GOOD.replace("      - run: make check",
                              "      - env:\n          T: %s\n            # ${{ secrets.DEPLOY_TOKEN }}\n        run: true" % header)
            self.assertRejected(wf, "secrets references are forbidden")

    def test_n10_wide_dash(self):
        wf = GOOD.replace("      - run: make check", "      -   run: |\n            make check\n          uses: evil/act@main")
        code, out = run(wf)
        self.assertEqual(code, 1, out)

    def test_n11_comment_shaped_run_lines(self):
        for header in ("|", ">", "|+"):
            wf = GOOD.replace("      - run: make check",
                              "      - run: %s\n          # ${{ github.event.pull_request.body }}\n          make check" % header)
            self.assertRejected(wf, "expressions in run: are forbidden")

    def test_n15_sequence_entry_block_scalars(self):
        for header in ("|", ">-"):
            wf = GOOD.replace("    timeout-minutes: 10", "    timeout-minutes: 10\n    strategy:\n      matrix:\n"
                              "        x:\n          - %s\n            # ${{ secrets.TOKEN }}" % header)
            self.assertRejected(wf, "secrets references are forbidden")

    def test_n18_unicode_whitespace_and_controls(self):
        for ch in ("\u00a0", "\u3000", "\u2003", "\u200b", "\u2028", "\u0085", "\ufeff", "\x0c", "\x0b", "\r"):
            with self.subTest(ch=repr(ch)):
                wf = GOOD.replace("          persist-credentials: false", "          %spersist-credentials: false" % ch)
                self.assertRejected(wf, "only printable ASCII")

    def test_n19_on_key_and_case_duplicates(self):
        self.assertRejected(GOOD.replace("on:\n", "On:\n"), "key On must be written in lower case")
        self.assertRejected(GOOD.replace("on:\n  pull_request:", "On: pull_request_target"), "key On")
        self.assertRejected(GOOD.replace("on:\n  pull_request:\n", ""), "triggers under the key 'on'")
        wf = GOOD.replace("          persist-credentials: false",
                          "          persist-credentials: false\n          PERSIST-CREDENTIALS: true")
        self.assertRejected(wf, "PERSIST-CREDENTIALS")
        # Case-insensitive duplicates of non-policy keys are rejected too.
        wf = GOOD.replace("    runs-on: ubuntu-24.04", "    runs-on: ubuntu-24.04\n    Runs-On: windows-latest")
        self.assertRejected(wf, "duplicate key")

    def test_n20_timeouts_and_documents(self):
        self.assertRejected(GOOD.replace("timeout-minutes: 10", "timeout-minutes: 0"), "numeric timeout-minutes")
        self.assertRejected(GOOD.replace("timeout-minutes: 10", "timeout-minutes: 1e3"), "numeric timeout-minutes")
        self.assertRejected("---\n---\n" + GOOD, "multi-document")

    def test_anchors_aliases_tags_merge(self):
        self.assertRejected(GOOD.replace("    runs-on: ubuntu-24.04", "    runs-on: &r ubuntu-24.04"), "anchors")
        self.assertRejected(GOOD.replace("    runs-on: ubuntu-24.04", "    runs-on: !!str ubuntu-24.04"), "explicit tags")
        self.assertRejected(GOOD.replace("    runs-on: ubuntu-24.04", "    runs-on: ubuntu-24.04\n    <<: {timeout-minutes: 5}"),
                            "merge keys")
        self.assertRejected(GOOD.replace("    runs-on: ubuntu-24.04", "    ? [a, b]\n    : x\n    runs-on: ubuntu-24.04"),
                            "complex mapping keys")

    def test_secrets_as_key_and_trigger_case(self):
        wf = GOOD.replace("    timeout-minutes: 10", "    timeout-minutes: 10\n    secrets: inherit")
        self.assertRejected(wf, "secrets references are forbidden")
        self.assertRejected(GOOD.replace("  pull_request:", "  PULL_REQUEST_TARGET:"), "trigger is forbidden")

    def test_p1_path_form_checkout(self):
        sha = SHA
        for ref in ("actions/checkout/@%s", "actions/checkout//@%s", "actions/checkout/.@%s",
                    "actions/checkout/./@%s", "actions/checkout/..@%s", "actions\\checkout@%s"):
            with self.subTest(ref=ref):
                wf = GOOD.replace("actions/checkout@%s # v7.0.1" % sha, ref % sha)
                code, out = run(wf)
                self.assertEqual(code, 1, out)
        wf = GOOD.replace("actions/checkout@%s" % sha, "actions/checkout/sub@%s" % sha).replace(
            "          persist-credentials: false\n", "")
        self.assertRejected(wf, "persist-credentials")
        wf = GOOD.replace("actions/checkout@%s" % sha, "Actions/Checkout@%s" % sha)
        self.assertRejected(wf, "not recorded in CI-PINS.md")

    def test_n21_case_variant_policy_keys(self):
        for old, new in (("    steps:", "    Steps:"), ("      - run: make check", "      - Run: make check"),
                         ("        with:", "        With:"), ("    timeout-minutes", "    Timeout-Minutes")):
            with self.subTest(key=new):
                self.assertRejected(GOOD.replace(old, new), "must be written in lower case")

    def test_n22_directives_rejected(self):
        for directive in ("%YAML 1.1", "%YAML 1.2", "%TAG ! tag:example.invalid,2026:"):
            with self.subTest(directive=directive):
                self.assertRejected(directive + "\n---\n" + GOOD, "directives")

    def test_n23_github_token_is_a_secret(self):
        wf = GOOD.replace("      - run: make check", "      - env:\n          T: ${{ github.token }}\n        run: true")
        self.assertRejected(wf, "secrets references are forbidden")

    def test_n24_depth_cap(self):
        deep = "x: " + "[" * 70 + "]" * 70 + "\n"
        self.assertRejected(GOOD + deep, "nesting deeper")

    def test_n26_job_permissions_and_empty_jobs_and_size(self):
        wf = GOOD.replace("    timeout-minutes: 10", "    timeout-minutes: 10\n    permissions:\n      contents: read\n      id-token: write")
        self.assertRejected(wf, "requests write or broad permissions")
        self.assertRejected(GOOD.split("jobs:")[0] + "jobs: {}\n", "jobs as a mapping")
        self.assertRejected(GOOD + "# " + "x" * (1024 * 1024) + "\n", "exceeds")

    def test_null_keys_rejected(self):
        self.assertRejected(GOOD + "~: x\n", "empty or null mapping keys")

    def test_uses_checked_at_any_depth(self):
        wf = GOOD.replace("    timeout-minutes: 10", "    timeout-minutes: 10\n    services:\n      db:\n        uses: evil/act@main")
        self.assertRejected(wf, "not pinned")

    def test_quoted_matrix_items_allowed(self):
        # FP1: real parser accepts quoted sequence items.
        wf = GOOD.replace("    timeout-minutes: 10", "    timeout-minutes: 10\n    strategy:\n      matrix:\n"
                          "        python: [\"3.10\", \"3.11\"]\n        port:\n          - \"6379:6379\"")
        self.assertEqual(run(wf)[0], 0)

    def test_realistic_script_accepted(self):
        wf = GOOD.replace("      - run: make check", "      - env:\n          MSG: it's ok\n        run: |\n"
                          "          # shell comment: with colon and 'quotes'\n          echo \"${MSG:-x}\" # trailing\n"
                          "          curl https://example.invalid/a#frag")
        self.assertEqual(run(wf)[0], 0)

    def test_invalid_yaml_and_utf8(self):
        self.assertRejected(GOOD + "  bad: [unclosed\n", "invalid YAML")
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp) / "wf.yml"
            wf.write_bytes(b"on: push\nname: \xff\n")
            pins = Path(tmp) / "pins.md"
            pins.write_text(PINS)
            proc = subprocess.run([sys.executable, str(CHECKER), "--pins", str(pins), str(wf)],
                                  capture_output=True, text=True, timeout=30)
            self.assertIn("not valid UTF-8", proc.stdout)


CLA_SHA = "ca4a40a7d1004f18d9960b404b97e5f30a505a08"
CLA_PINS = PINS + "| contributor-assistant/github-action | %s |\n" % CLA_SHA
CLA = (ROOT / ".github/workflows/cla.yml").read_text()


def run_named(name, workflow, pins=CLA_PINS):
    with tempfile.TemporaryDirectory() as tmp:
        wf = Path(tmp) / name
        wf.write_text(workflow)
        pin_file = Path(tmp) / "pins.md"
        pin_file.write_text(pins)
        proc = subprocess.run([sys.executable, str(CHECKER), "--pins", str(pin_file), str(wf)], capture_output=True, text=True, timeout=30)
        return proc.returncode, proc.stdout


class ClaException(unittest.TestCase):
    """The contributor-agreement bot is the one reviewed exception, and only in a file named cla.yml with exactly its shape."""

    def bad(self, workflow, fragment, name="cla.yml"):
        code, out = run_named(name, workflow)
        self.assertEqual(code, 1, out)
        self.assertIn(fragment, out)

    def test_the_committed_cla_workflow_is_accepted(self):
        self.assertEqual(run_named("cla.yml", CLA)[0], 0)

    def test_the_same_file_under_another_name_is_refused(self):
        self.bad(CLA, "pull_request_target trigger is forbidden", name="other.yml")

    def test_extra_triggers_steps_or_shell_are_refused(self):
        self.bad(CLA.replace("      - closed\n", "      - closed\n      - labeled\n"), "triggers must be exactly")
        self.bad(CLA + "      - run: echo hi\n", "exactly one step")
        self.bad(CLA.replace("        uses:", "        run: echo hi\n        uses:"), "unexpected step key run")
        self.bad(CLA.replace("      - name: CLA Assistant\n", "      - uses: actions/checkout@%s\n        with:\n          persist-credentials: false\n      - name: CLA Assistant\n" % SHA), "exactly one step")

    def test_broader_permissions_or_a_different_action_are_refused(self):
        self.bad(CLA.replace("      actions: write\n", "      actions: write\n      contents: write\n").replace("      contents: read\n      pull-requests", "      pull-requests"), "job permissions must be exactly")
        self.bad(CLA.replace("contributor-assistant/github-action@", "evil/action@"), "must use contributor-assistant/github-action")
        self.bad(CLA.replace(CLA_SHA, "v2.6.1"), "must use contributor-assistant/github-action")

    def test_an_unrecorded_pin_extra_secret_or_unknown_input_is_refused(self):
        code, out = run_named("cla.yml", CLA, pins=PINS)
        self.assertEqual(code, 1)
        self.assertIn("not recorded in CI-PINS.md", out)
        self.bad(CLA.replace("          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n", "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          OTHER: ${{ secrets.OTHER }}\n"), "env must be exactly")
        self.bad(CLA.replace("          branch: main\n", "          branch: main\n          exec: rm\n"), "input the policy does not know")

    def test_it_must_stay_inert_until_enabled(self):
        self.bad(CLA.replace("vars.CLA_ENABLED == 'true' && ", ""), "inert until")


if __name__ == "__main__":
    unittest.main()

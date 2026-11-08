"""INSTALLING.md names the options and commands that exist: the proxy and lockout paragraphs cannot drift from the code (M0-E01-S12, finding F-03)."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "INSTALLING.md").read_text()


def src(*parts):
    return (ROOT.joinpath(*parts)).read_text()


class Doc(unittest.TestCase):
    def test_the_proxy_options_it_names_exist_in_the_api(self):
        run = src("backend", "cmd", "api", "run.go")
        for flag in ("--behind-tls-proxy", "--proxy-address-header"):
            self.assertIn(flag, DOC)
            self.assertIn(flag.lstrip("-"), run, flag)
        self.assertIn("X-Forwarded-For", DOC)
        self.assertIn('"X-Forwarded-For"', run, "the default header the document names")
        self.assertIn("rightmost", DOC)

    def test_user_unlock_exists_and_is_described_as_the_restart_it_is(self):
        self.assertIn("svavyom-ctl user-unlock --apply", DOC)
        self.assertIn('case "user-unlock":', src("backend", "cmd", "svavyom-ctl", "main.go"))
        self.assertIn("no per-user unlock", DOC)

    def test_the_thresholds_it_states_are_the_limiters(self):
        lim = src("backend", "internal", "auth", "limiter.go")
        want = {"failFree": "five", "sourceFree": "twenty"}
        for name, word in want.items():
            n = int(re.search(r"%s\s*=\s*([0-9]+)" % name, lim).group(1))
            self.assertEqual({5: "five", 20: "twenty"}[n], word, name)
            self.assertIn(word, DOC, name)
        self.assertIn("15 minutes", DOC)
        self.assertRegex(lim, r"maxBlock\s*=\s*15 \* time\.Minute")
        self.assertRegex(lim, r"slowMax\s*=\s*2 \* time\.Second")

    def test_the_pool_sentence_matches_the_units(self):
        self.assertIn("mutation service can see that a volume exists", DOC)
        self.assertNotIn("no Svavyom service can read it", DOC)


if __name__ == "__main__":
    unittest.main()

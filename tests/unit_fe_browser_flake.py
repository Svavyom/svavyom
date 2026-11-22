"""The browser tier tolerates a scenario that fails once under load (finding N6) but never hides a real failure: at most two retries, and the list reporter, which names
every scenario that needed one. Raising the number or dropping the reporter is a decision, not a drive-by edit."""
import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
CONFIG = (Path(__file__).resolve().parent.parent / "frontend" / "playwright.config.ts").read_text()


class BrowserTierRetries(unittest.TestCase):
    def test_retries_are_two_and_no_more(self):
        self.assertEqual(re.findall(r"^\s*retries:\s*(\d+),", CONFIG, re.M), ["2"])

    def test_the_list_reporter_stays_so_a_flaky_scenario_is_named(self):
        self.assertRegex(CONFIG, r'reporter:\s*\[\["list"\]\]')

    def test_a_focused_test_still_fails_the_run(self):
        self.assertRegex(CONFIG, r"forbidOnly:\s*true")


if __name__ == "__main__":
    unittest.main()

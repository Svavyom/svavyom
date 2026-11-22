"""Pins the statement the operator documents make about rolling back across a database change (finding N4 of the 2026-11-14 plan): older code does NOT ignore a newer
schema, so a rollback past a schema change is refused without the pre-upgrade database copy (--restore-db), and users, keys and settings made since are lost."""
import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


class RollbackAcrossASchemaChange(unittest.TestCase):
    def text(self, name):
        return re.sub(r"\s+", " ", (ROOT / name).read_text())

    def test_installing_says_it_is_refused_without_the_database_copy_and_what_is_lost(self):
        t = self.text("INSTALLING.md")
        self.assertIn("--restore-db", t)
        self.assertRegex(t, r"refused unless you give `--restore-db`")
        self.assertRegex(t, r"users, keys and settings made since then are lost")

    def test_the_changelog_names_the_flag_for_each_release_that_changed_the_database(self):
        t = self.text("CHANGELOG.md")
        self.assertRegex(t, r"Rolling back to preview\.17 needs `--restore-db`")
        self.assertRegex(t, r"Rolling back needs `--restore-db`")

    def test_no_document_claims_that_older_code_ignores_new_tables(self):
        for name in ("INSTALLING.md", "USING.md", "CHANGELOG.md", "README.md"):
            self.assertNotRegex(self.text(name), r"(?i)older (code|versions?) (ignores?|will ignore) (the )?new tables")


if __name__ == "__main__":
    unittest.main()

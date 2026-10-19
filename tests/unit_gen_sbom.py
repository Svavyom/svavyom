"""Tests of the SBOM / licence generator's pure parts (tools/gen_sbom.py). The module-cache walk itself runs in `make licenses`."""
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import gen_sbom as g  # noqa: E402

MIT = "Copyright (c) 2020 X\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software..."
BSD3 = "Redistribution and use in source and binary forms, with or without modification, are permitted provided that: ... Neither the name of the copyright holder nor the names..."
BSD2 = "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:"
APACHE = "Apache License\nVersion 2.0, January 2004"
GPL = "GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007"


class Detect(unittest.TestCase):
    def test_known_texts(self):
        for text, want in ((MIT, "MIT"), (BSD3, "BSD-3-Clause"), (BSD2, "BSD-2-Clause"), (APACHE, "Apache-2.0"),
                           ("Mozilla Public License Version 2.0", "MPL-2.0"), ("This is free and unencumbered software released into the public domain", "Unlicense")):
            self.assertEqual(g.detect(text), want)

    def test_unknown_text_is_never_guessed(self):
        self.assertEqual(g.detect(GPL), "UNKNOWN")
        self.assertEqual(g.detect("All rights reserved."), "UNKNOWN")
        self.assertEqual(g.detect(""), "UNKNOWN")

    def test_whitespace_does_not_matter(self):
        self.assertEqual(g.detect(MIT.replace(" ", "\n  ")), "MIT")


class Policy(unittest.TestCase):
    def test_policy_has_no_unknown_and_matches_the_shipped_licences(self):
        pol = json.loads((ROOT / g.POLICY).read_text())
        self.assertNotIn("UNKNOWN", pol["approved"])
        self.assertNotIn("NOASSERTION", pol["approved"], "the top-level licence is not a dependency licence")
        for lic in json.loads((ROOT / g.LICENSES).read_text())["components"]:
            self.assertIn(lic["status"], ("approved", "exception"), lic["name"])
            self.assertNotEqual(lic["license"], "UNKNOWN", lic["name"])

    def test_the_root_component_carries_the_product_licence(self):
        doc = json.loads((ROOT / g.SBOM).read_text())
        self.assertEqual(doc["metadata"]["component"]["licenses"], [{"license": {"id": "AGPL-3.0-or-later"}}])
        self.assertEqual((doc["bomFormat"], doc["specVersion"]), ("CycloneDX", "1.5"))

    def test_every_shipped_go_module_is_in_the_notices(self):
        notices = (ROOT / g.NOTICES).read_text()
        for c in json.loads((ROOT / g.LICENSES).read_text())["components"]:
            if c["ecosystem"] == "golang":
                self.assertIn("## %s %s" % (c["name"], c["version"]), notices)


if __name__ == "__main__":
    unittest.main()

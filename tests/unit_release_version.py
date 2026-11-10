"""The release build stamps the version into the API: without it the dashboard and the status page report "dev" for every release."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*p):
    with open(os.path.join(ROOT, *p)) as f:
        return f.read()


class ReleaseVersion(unittest.TestCase):
    def test_the_api_declares_the_variable_the_build_sets(self):
        self.assertRegex(read("backend", "cmd", "api", "main.go"), r'(?m)^var version = "dev"')

    def test_every_go_binary_is_built_with_the_version_stamp(self):
        s = read("toolchain", "release", "build-binaries.sh")
        self.assertIn('v=$(cat ../VERSION)', s)
        build = re.search(r"build\(\) \{.*?\n\}", s, re.S).group(0)
        self.assertIn("-X main.version=$v", build)
        self.assertIn("-X main.Version=$v", s)  # svavyom-ctl keeps its own variable

    def test_the_version_file_is_a_release_version(self):
        self.assertRegex(read("VERSION").strip(), r"^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$")


if __name__ == "__main__":
    unittest.main()

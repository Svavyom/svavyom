import unittest
from pathlib import Path
class SafetyBaseline(unittest.TestCase):
    def test_installer_is_inspection_only(self):
        s=(Path(__file__).parents[1]/'packages/installer/inspect-only.sh').read_text()
        self.assertIn('SAFE INSPECTION ONLY',s)

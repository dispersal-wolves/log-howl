import re
import unittest
from pathlib import Path

from log_howl import Rule, Suppressor, match_line, redact_line


class LogHowlTests(unittest.TestCase):
    def test_matches_and_redacts(self):
        rules = [Rule("failed-login", "warning", re.compile("failed", re.I))]
        events = match_line(Path("auth.log"), "Failed login token=secret-value", rules)
        self.assertEqual(events[0]["rule"], "failed-login")
        self.assertNotIn("secret-value", events[0]["message"])

    def test_suppresses_within_window(self):
        suppressor = Suppressor(60)
        self.assertTrue(suppressor.permits("x", now=1))
        self.assertFalse(suppressor.permits("x", now=2))
        self.assertTrue(suppressor.permits("x", now=62))


if __name__ == "__main__":
    unittest.main()

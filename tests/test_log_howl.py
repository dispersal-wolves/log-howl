import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from log_howl import Rule, Suppressor, main, match_line, redact_line


class LogHowlTests(unittest.TestCase):
    def test_matches_and_redacts(self):
        rules = [Rule("failed-login", "warning", re.compile("failed", re.I))]
        events = match_line(Path("auth.log"), "Failed login token=secret-value", rules)
        self.assertEqual(events[0]["rule"], "failed-login")
        self.assertNotIn("secret-value", events[0]["message"])

    def test_redacts_authorization_scheme_values(self):
        for line in ("Authorization: Bearer abc123", "authorization=Basic dXNlcjpwYXNz"):
            redacted = redact_line(line)
            self.assertIn("[REDACTED]", redacted)
            self.assertNotIn("abc123", redacted)
            self.assertNotIn("dXNlcjpwYXNz", redacted)

    def test_rejects_plain_http_webhook_at_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp, "app.log")
            log.write_text("", encoding="utf-8")
            config = Path(tmp, "rules.json")
            config.write_text(json.dumps({
                "files": [str(log)],
                "webhook": "http://example.invalid/hook",
                "rules": [{"name": "any", "pattern": "x"}],
            }), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main(["watch", "--config", str(config)]), 2)
            self.assertIn("HTTPS", err.getvalue())

    def test_suppresses_within_window(self):
        suppressor = Suppressor(60)
        self.assertTrue(suppressor.permits("x", now=1))
        self.assertFalse(suppressor.permits("x", now=2))
        self.assertTrue(suppressor.permits("x", now=62))


if __name__ == "__main__":
    unittest.main()

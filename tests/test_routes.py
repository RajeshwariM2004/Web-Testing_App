"""Smoke tests for routes and JSON API: python -m unittest discover -s tests -v"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("FLASK_SECRET_KEY", "test-secret")

import app as wast_app  # noqa: E402


class TestRoutes(unittest.TestCase):
    def setUp(self) -> None:
        wast_app.app.config.update(TESTING=True)
        self.client = wast_app.app.test_client()

    def test_home_ok(self) -> None:
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"scan", r.data.lower())

    def test_scan_get_redirects_home(self) -> None:
        r = self.client.get("/scan", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        loc = r.headers.get("Location", "")
        self.assertIn("/", loc)

    def test_scan_status_404(self) -> None:
        r = self.client.get("/api/scan/999999/status")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json().get("error"), "not_found")

    def test_results_unknown(self) -> None:
        r = self.client.get("/results/999999", follow_redirects=True)
        self.assertEqual(r.status_code, 200)

    def test_report_unknown(self) -> None:
        r = self.client.get("/report/999999", follow_redirects=True)
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()

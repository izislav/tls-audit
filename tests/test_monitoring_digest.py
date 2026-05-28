import unittest
from unittest.mock import patch

try:
    from services.api.app import main
except Exception:
    main = None


@unittest.skipUnless(main is not None, "api dependencies are unavailable")
class MonitoringDigestTests(unittest.TestCase):
    def test_build_monitoring_digest_payload_includes_links_and_priority(self) -> None:
        export_payload = {
            "generated_at": "2026-05-28T10:00:00+00:00",
            "items": [
                {
                    "subscription_id": 11,
                    "host": "example.ru",
                    "port": 443,
                    "plan": "pro",
                    "ownership_verified": True,
                    "last_sent_at": "2026-05-27T10:00:00+00:00",
                    "next_run_at": "2026-05-28T10:00:00+00:00",
                    "events": [
                        {
                            "event_type": "grade_degraded",
                            "severity": "high",
                            "title": "Оценка ухудшилась",
                            "created_at": "2026-05-28T09:00:00+00:00",
                            "scan_id": "scan-1",
                        },
                        {
                            "event_type": "hsts_changed",
                            "severity": "info",
                            "title": "HSTS changed",
                            "created_at": "2026-05-28T10:00:00+00:00",
                            "scan_id": "scan-2",
                        },
                    ],
                }
            ],
        }
        with patch.object(main, "build_monitoring_export_payload", return_value=export_payload):
            digest = main.build_monitoring_digest_payload("admin@example.ru", "token-1", 20, 20)

        self.assertEqual(digest["email"], "admin@example.ru")
        self.assertTrue(digest["manage_url"].endswith("/monitor-status?token=token-1"))
        item = digest["items"][0]
        self.assertEqual(item["critical_high_count"], 1)
        self.assertEqual(item["latest_scan_id"], "scan-1")
        self.assertIn("/scan?job=scan-1", item["latest_scan_url"])
        self.assertIn("/api/report/scan-1/compare", item["latest_diff_url"])
        self.assertEqual(item["top_events"][0]["severity"], "high")

    def test_build_monitoring_digest_payload_marks_paused_without_ownership(self) -> None:
        export_payload = {
            "generated_at": "2026-05-28T10:00:00+00:00",
            "items": [
                {
                    "subscription_id": 12,
                    "host": "paused.ru",
                    "port": 443,
                    "plan": "pro",
                    "ownership_verified": False,
                    "events": [],
                }
            ],
        }
        with patch.object(main, "build_monitoring_export_payload", return_value=export_payload):
            digest = main.build_monitoring_digest_payload("admin@example.ru", "token-2", 20, 20)
        self.assertEqual(digest["items"][0]["delivery_status"], "paused_ownership")


if __name__ == "__main__":
    unittest.main()

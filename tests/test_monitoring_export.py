import unittest

from shared.tls_audit.monitor_export import monitoring_export_to_csv


class MonitoringExportTests(unittest.TestCase):
    def test_monitoring_export_to_csv_writes_rows_with_events(self) -> None:
        payload = {
            "items": [
                {
                    "subscription_id": 7,
                    "host": "example.ru",
                    "port": 443,
                    "plan": "pro",
                    "enabled": True,
                    "confirmed": True,
                    "ownership_verified": True,
                    "last_sent_at": "2026-05-25T10:00:00+00:00",
                    "next_run_at": "2026-05-26T10:00:00+00:00",
                    "events": [
                        {
                            "event_type": "grade_degraded",
                            "severity": "high",
                            "title": "Оценка TLS ухудшилась",
                            "detail": "Изменение баллов: -8.",
                            "created_at": "2026-05-25T10:01:00+00:00",
                        }
                    ],
                }
            ]
        }
        csv_text = monitoring_export_to_csv(payload)
        self.assertIn("subscription_id,host,port,plan", csv_text)
        self.assertIn("example.ru,443,pro,True,True,True", csv_text)
        self.assertIn("grade_degraded,high", csv_text)

    def test_monitoring_export_to_csv_writes_row_without_events(self) -> None:
        payload = {
            "items": [
                {
                    "subscription_id": 8,
                    "host": "noevents.ru",
                    "port": 443,
                    "plan": "free",
                    "enabled": True,
                    "confirmed": True,
                    "ownership_verified": False,
                    "last_sent_at": "",
                    "next_run_at": "",
                    "events": [],
                }
            ]
        }
        csv_text = monitoring_export_to_csv(payload)
        self.assertIn("noevents.ru,443,free,True,True,False", csv_text)


if __name__ == "__main__":
    unittest.main()

import os
import unittest
from unittest.mock import patch

from shared.tls_audit.monitoring import MonitoringEvent
from shared.tls_audit.jobs import InMemoryJobStore
from shared.tls_audit.monitoring_store import InMemoryMonitoringStore
from services.worker import worker
from shared.tls_audit.monitoring import MonitoringDiff, FindingSummary


class WorkerMonitoringTests(unittest.TestCase):
    def test_alert_key_for_critical_added_uses_code(self) -> None:
        event = MonitoringEvent(
            event_type="critical_added",
            severity="critical",
            title="Критичная проблема",
            payload={"code": "certificate_expired", "title": "Сертификат истёк"},
        )
        self.assertEqual(worker.alert_key_for_event(event), "critical_added:certificate_expired")

    def test_alert_key_for_legacy_tls_uses_protocols(self) -> None:
        event = MonitoringEvent(
            event_type="legacy_tls_enabled",
            severity="high",
            title="Включился устаревший TLS",
            payload={"added_protocols": ["TLS 1.1", "TLS 1.0"]},
        )
        self.assertEqual(worker.alert_key_for_event(event), "legacy_tls_enabled:TLS 1.0,TLS 1.1")

    def test_handle_job_records_monitoring_snapshot_for_scheduled_scan(self) -> None:
        job_store = InMemoryJobStore()
        monitoring_store = InMemoryMonitoringStore()
        monitoring_store.upsert_domain("example.ru")
        job = job_store.create("example.ru", 443, ["93.184.216.34"])

        with patch.object(worker, "job_store", job_store), patch.object(
            worker, "archive_store"
        ) as archive_store, patch.object(
            worker, "monitoring_store", monitoring_store
        ), patch.object(
            worker.subscription_store, "mark_sent"
        ) as mark_sent, patch.object(
            worker, "send_email", return_value=True
        ) as send_email, patch.object(
            worker, "ownership_verified", return_value=True
        ), patch.object(
            worker.subscription_store, "enabled", True
        ), patch.object(
            worker, "log_event"
        ), patch.object(
            worker, "validate_worker_target"
        ) as validate_worker_target, patch.object(
            worker, "run_full_scan"
        ) as run_full_scan, patch.object(
            worker, "release_target"
        ), patch.dict(
            os.environ,
            {
                "SMTP_URL": "smtps://example:465",
                "SMTP_USER": "u",
                "SMTP_PASSWORD": "p",
                "ALERT_EMAIL_FROM": "info@example.ru",
                "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
            },
            clear=False,
        ):
            validate_worker_target.return_value.host = "example.ru"
            validate_worker_target.return_value.port = 443
            validate_worker_target.return_value.addresses = ["93.184.216.34"]
            run_full_scan.return_value.to_dict.return_value = {
                "host": "example.ru",
                "port": 443,
                "grade": "A",
                "score": 95,
                "findings": [
                    {"severity": "high", "title": "TLS 1.0 включён"},
                    {"severity": "medium", "title": "Нет HSTS"},
                ],
            }

            result = worker.handle_job(
                {
                    "id": job.id,
                    "host": "example.ru",
                    "port": 443,
                    "addresses": ["93.184.216.34"],
                    "monitored_domain_id": 1,
                    "subscription_id": 22,
                    "subscription_email": "admin@example.ru",
                    "subscription_plan": "support",
                    "trigger": "scheduled",
                }
            )

        self.assertEqual(result["status"], "done")
        archive_store.save_report.assert_called()
        self.assertTrue(send_email.called)
        bodies = [call.kwargs.get("body", "") for call in send_email.call_args_list]
        self.assertTrue(any("Что делать сейчас" in body for body in bodies))
        mark_sent.assert_called_once_with(22)

    def test_send_subscription_report_includes_diff_summary(self) -> None:
        job = {
            "id": "job-1",
            "host": "example.ru",
            "port": 443,
            "subscription_id": 7,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "support",
        }
        report = {
            "grade": "B",
            "score": 81,
            "summary": ["Есть замечания"],
            "findings": [],
            "raw": {
                "provenance": {
                    "sources": [
                        {
                            "id": "basic_scanner",
                            "status": "done",
                            "version": "0.2.1",
                            "scanned_at": "2026-05-26T12:00:00Z",
                        }
                    ]
                }
            },
        }
        diff = MonitoringDiff(
            grade_degraded=True,
            score_delta=-9,
            added_findings=[FindingSummary("a", "A", "high", "tls")],
            resolved_findings=[FindingSummary("b", "B", "high", "tls")],
        )
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "mark_sent"
        ) as mark_sent, patch.object(
            worker.subscription_store, "should_send_report", return_value=True
        ), patch.object(
            worker, "ownership_verified", return_value=True
        ), patch.object(
            worker.subscription_store, "mark_report_sent"
        ) as mark_report_sent, patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465", "PUBLIC_BASE_URL": "http://127.0.0.1:8000"},
            clear=False,
        ):
            worker.send_subscription_report(job, report, diff)
        body = send_email.call_args.kwargs["body"]
        self.assertIn("Security status digest", body)
        self.assertIn("Критические изменения:", body)
        self.assertIn("Оценка стала ниже", body)
        self.assertIn("Добавлены важные риски: A", body)
        self.assertIn("Исправлены важные риски: B", body)
        self.assertIn("Полный отчёт:", body)
        mark_sent.assert_called_once_with(7)
        mark_report_sent.assert_called_once_with(7, "job-1")

    def test_send_subscription_report_free_plan_is_concise(self) -> None:
        job = {
            "id": "job-2",
            "host": "example.ru",
            "port": 443,
            "subscription_id": 8,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "free",
        }
        report = {"grade": "A", "score": 93, "summary": ["Стабильная конфигурация"], "findings": []}
        diff = MonitoringDiff(grade_improved=True, score_delta=4)
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "mark_sent"
        ), patch.object(
            worker.subscription_store, "should_send_report", return_value=True
        ), patch.object(
            worker.subscription_store, "mark_report_sent"
        ), patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465", "PUBLIC_BASE_URL": "http://127.0.0.1:8000"},
            clear=False,
        ):
            worker.send_subscription_report(job, report, diff)
        body = send_email.call_args.kwargs["body"]
        self.assertIn("базовый еженедельный отчёт", body)
        self.assertNotIn("Изменения с прошлого скана", body)
        self.assertNotIn("Главные замечания", body)

    def test_top_findings_groups_repeated_titles(self) -> None:
        report = {
            "findings": [
                {
                    "severity": "medium",
                    "title": "Сервер принимает слабый cipher suite",
                    "detail": "AES256-SHA: CBC cipher without AEAD.",
                },
                {
                    "severity": "medium",
                    "title": "Сервер принимает слабый cipher suite",
                    "detail": "ECDHE-RSA-AES128-SHA: CBC cipher without AEAD.",
                },
                {
                    "severity": "high",
                    "title": "TLS 1.0 включён",
                    "detail": "",
                },
            ]
        }
        text = worker.top_findings(report, limit=3)
        self.assertIn("TLS 1.0 включён", text)
        self.assertIn("Сервер принимает слабый cipher suite (x2)", text)
        self.assertIn("AES256-SHA: CBC cipher without AEAD.", text)

    def test_format_certificate_status(self) -> None:
        self.assertIn("требуется продление", worker.format_certificate_status(10, "2026-06-10T00:00:00Z"))
        self.assertIn("истёк", worker.format_certificate_status(-2, "2026-05-01T00:00:00Z"))
        self.assertEqual(worker.format_certificate_status(None, None), "нет данных")

    def test_format_provenance_block_ignores_missing(self) -> None:
        self.assertEqual(worker.format_provenance_block({}), "")

    def test_send_subscription_report_skips_duplicate_scan(self) -> None:
        job = {
            "id": "job-dup",
            "host": "example.ru",
            "port": 443,
            "subscription_id": 8,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "free",
        }
        report = {"grade": "A", "score": 93, "summary": ["Стабильная конфигурация"], "findings": []}
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "should_send_report", return_value=False
        ), patch.object(
            worker.subscription_store, "mark_report_sent"
        ) as mark_report_sent, patch.object(
            worker.subscription_store, "mark_sent"
        ) as mark_sent, patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465", "PUBLIC_BASE_URL": "http://127.0.0.1:8000"},
            clear=False,
        ):
            worker.send_subscription_report(job, report, None)
        send_email.assert_not_called()
        mark_report_sent.assert_not_called()
        mark_sent.assert_not_called()

    def test_send_subscription_report_respects_report_cooldown(self) -> None:
        job = {
            "id": "job-cooldown",
            "host": "example.ru",
            "port": 443,
            "subscription_id": 18,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "free",
        }
        report = {"grade": "A", "score": 93, "summary": ["Стабильная конфигурация"], "findings": []}
        should_send_effect = [True, False]
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "should_send_report", return_value=True
        ), patch.object(
            worker.subscription_store, "should_send_alert", side_effect=should_send_effect
        ), patch.object(
            worker.subscription_store, "mark_report_sent"
        ) as mark_report_sent, patch.object(
            worker.subscription_store, "mark_alert_sent"
        ) as mark_alert_sent, patch.object(
            worker.subscription_store, "mark_sent"
        ) as mark_sent, patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465", "PUBLIC_BASE_URL": "http://127.0.0.1:8000"},
            clear=False,
        ):
            worker.send_subscription_report(job, report, None)
            worker.send_subscription_report(job, report, None)
        self.assertEqual(send_email.call_count, 1)
        mark_report_sent.assert_called_once_with(18, "job-cooldown")
        mark_sent.assert_called_once_with(18)
        mark_alert_sent.assert_called_once_with(18, "weekly_report")

    def test_send_subscription_failure_report_marks_critical_delivery(self) -> None:
        job = {
            "id": "job-3",
            "host": "down.example.ru",
            "subscription_id": 9,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "support",
        }
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "mark_alert_sent"
        ) as mark_alert_sent, patch.object(
            worker.subscription_store, "should_send_alert", return_value=True
        ), patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465"},
            clear=False,
        ):
            worker.send_subscription_failure_report(job, "timeout")
        self.assertIn("critical", send_email.call_args.kwargs["subject"].lower())
        self.assertIn("timeout", send_email.call_args.kwargs["body"])
        mark_alert_sent.assert_called_once_with(9, "scan_failed")

    def test_send_subscription_alert_report_for_support_plan(self) -> None:
        job = {
            "id": "job-4",
            "host": "alert.example.ru",
            "subscription_id": 10,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "support",
        }
        events = [
            MonitoringEvent(
                event_type="certificate_expiring",
                severity="high",
                title="Сертификат скоро истечет",
                detail="осталось 7 дней",
            ),
            MonitoringEvent(
                event_type="certificate_expired",
                severity="critical",
                title="Сертификат истек",
                detail="notAfter in past",
            ),
        ]
        report = {"grade": "C", "score": 70}
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "should_send_alert", return_value=True
        ), patch.object(
            worker, "ownership_verified", return_value=True
        ), patch.object(
            worker.subscription_store, "mark_alert_sent"
        ) as mark_alert_sent, patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465"},
            clear=False,
        ):
            worker.send_subscription_alert_report(job, events, report)
        bodies = [call.kwargs.get("body", "") for call in send_email.call_args_list]
        self.assertTrue(any("Сертификат скоро истечет" in body for body in bodies))
        self.assertTrue(any("Сертификат истек" in body for body in bodies))
        self.assertTrue(any("C (70/100)" in body for body in bodies))
        self.assertTrue(any("Owner digest JSON" in body for body in bodies))
        self.assertGreaterEqual(mark_alert_sent.call_count, 3)

    def test_send_subscription_alert_report_respects_daily_cooldown(self) -> None:
        job = {
            "id": "job-5",
            "host": "alert.example.ru",
            "subscription_id": 11,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "support",
        }
        events = [
            MonitoringEvent(
                event_type="certificate_expiring",
                severity="high",
                title="Сертификат скоро истечет",
                detail="осталось 7 дней",
            )
        ]
        report = {"grade": "B", "score": 80}
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "should_send_alert", return_value=False
        ), patch.object(
            worker, "ownership_verified", return_value=True
        ), patch.object(
            worker.subscription_store, "mark_alert_sent"
        ) as mark_alert_sent, patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465"},
            clear=False,
        ):
            worker.send_subscription_alert_report(job, events, report)
        send_email.assert_not_called()
        mark_alert_sent.assert_not_called()

    def test_send_subscription_alert_report_respects_batch_cooldown(self) -> None:
        job = {
            "id": "job-15",
            "host": "alert.example.ru",
            "subscription_id": 21,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "support",
        }
        events = [
            MonitoringEvent(
                event_type="grade_degraded",
                severity="high",
                title="Оценка ухудшилась",
                detail="-10",
            )
        ]
        report = {"grade": "C", "score": 72}
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "should_send_alert", side_effect=[False]
        ), patch.object(
            worker, "ownership_verified", return_value=True
        ), patch.object(
            worker.subscription_store, "mark_alert_sent"
        ) as mark_alert_sent, patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465"},
            clear=False,
        ):
            worker.send_subscription_alert_report(job, events, report)
        send_email.assert_not_called()
        mark_alert_sent.assert_not_called()

    def test_send_subscription_alert_report_includes_grade_degraded_event(self) -> None:
        job = {
            "id": "job-6",
            "host": "alert.example.ru",
            "subscription_id": 12,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "support",
        }
        events = [
            MonitoringEvent(
                event_type="grade_degraded",
                severity="high",
                title="Оценка TLS ухудшилась",
                detail="score delta -6",
            )
        ]
        report = {"grade": "B", "score": 83}
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "should_send_alert", return_value=True
        ), patch.object(
            worker, "ownership_verified", return_value=True
        ), patch.object(
            worker.subscription_store, "mark_alert_sent"
        ) as mark_alert_sent, patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465"},
            clear=False,
        ):
            worker.send_subscription_alert_report(job, events, report)
        body = send_email.call_args.kwargs["body"]
        self.assertIn("Оценка TLS ухудшилась", body)
        self.assertIn("Owner digest JSON", body)
        self.assertEqual(mark_alert_sent.call_count, 1)

    def test_send_subscription_alert_report_ignores_unimportant_events(self) -> None:
        job = {
            "id": "job-7",
            "host": "alert.example.ru",
            "subscription_id": 13,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "support",
        }
        events = [
            MonitoringEvent(
                event_type="hsts_changed",
                severity="medium",
                title="Изменилась HSTS-конфигурация",
            )
        ]
        report = {"grade": "B", "score": 83}
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.dict(
            os.environ,
            {"SMTP_URL": "smtps://example:465"},
            clear=False,
        ):
            worker.send_subscription_alert_report(job, events, report)
        send_email.assert_not_called()

    def test_send_subscription_report_support_requires_ownership_verification(self) -> None:
        job = {
            "id": "job-own-1",
            "host": "example.ru",
            "port": 443,
            "subscription_id": 31,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "support",
        }
        report = {"grade": "A", "score": 92, "summary": ["OK"], "findings": []}
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker.subscription_store, "should_send_report", return_value=True
        ), patch.object(
            worker, "ownership_verified", return_value=False
        ):
            worker.send_subscription_report(job, report, None)
        send_email.assert_not_called()

    def test_send_subscription_alert_report_support_requires_ownership_verification(self) -> None:
        job = {
            "id": "job-own-2",
            "host": "example.ru",
            "subscription_id": 32,
            "subscription_email": "admin@example.ru",
            "subscription_plan": "support",
        }
        events = [MonitoringEvent(event_type="scan_failed", severity="critical", title="scan failed")]
        report = {"grade": "C", "score": 60}
        with patch.object(worker, "send_email", return_value=True) as send_email, patch.object(
            worker, "ownership_verified", return_value=False
        ):
            worker.send_subscription_alert_report(job, events, report)
        send_email.assert_not_called()

    def test_handle_job_records_monitoring_failure_for_scheduled_scan(self) -> None:
        job_store = InMemoryJobStore()
        monitoring_store = InMemoryMonitoringStore()
        monitoring_store.upsert_domain("example.ru")
        job = job_store.create("example.ru", 443, ["93.184.216.34"])

        with patch.object(worker, "job_store", job_store), patch.object(
            worker, "archive_store"
        ), patch.object(worker, "monitoring_store", monitoring_store), patch.object(
            worker, "log_event"
        ), patch.object(
            worker, "validate_worker_target", side_effect=ValueError("DNS failed")
        ), patch.object(
            worker, "release_target"
        ):
            result = worker.handle_job(
                {
                    "id": job.id,
                    "host": "example.ru",
                    "port": 443,
                    "addresses": ["93.184.216.34"],
                    "monitored_domain_id": 1,
                }
            )

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "DNS failed")


if __name__ == "__main__":
    unittest.main()

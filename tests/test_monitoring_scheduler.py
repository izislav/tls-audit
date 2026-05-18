import unittest
from unittest.mock import patch

from shared.tls_audit.jobs import InMemoryJobStore
from shared.tls_audit.monitoring_scheduler import schedule_due_scans
from shared.tls_audit.monitoring_store import InMemoryMonitoringStore
from shared.tls_audit.traffic_control import TargetScanGuard


class MonitoringSchedulerTests(unittest.TestCase):
    def test_scheduler_enqueues_due_domain_and_marks_next_scan(self) -> None:
        monitoring_store = InMemoryMonitoringStore()
        domain = monitoring_store.upsert_domain("example.ru", scan_interval_seconds=3600)
        job_store = InMemoryJobStore()
        queued = []

        with patch(
            "shared.tls_audit.monitoring_scheduler.validate_target",
        ) as validate_target:
            validate_target.return_value.host = "example.ru"
            validate_target.return_value.port = 443
            validate_target.return_value.addresses = ["93.184.216.34"]

            result = schedule_due_scans(
                monitoring_store,
                job_store,
                queued.append,
            )

        self.assertEqual(len(result.queued), 1)
        self.assertEqual(result.queued[0].domain_id, domain.id)
        self.assertEqual(queued[0]["trigger"], "scheduled")
        self.assertEqual(queued[0]["monitored_domain_id"], domain.id)
        self.assertEqual(job_store.get(queued[0]["id"]).host, "example.ru")
        self.assertEqual(monitoring_store.due_domains(), [])

    def test_scheduler_skips_invalid_domain(self) -> None:
        monitoring_store = InMemoryMonitoringStore()
        monitoring_store.upsert_domain("localhost")
        job_store = InMemoryJobStore()
        queued = []

        result = schedule_due_scans(monitoring_store, job_store, queued.append)

        self.assertEqual(result.queued, [])
        self.assertEqual(result.skipped[0]["reason"], "validation_failed")
        self.assertEqual(queued, [])

    def test_scheduler_respects_target_guard_active_scan(self) -> None:
        monitoring_store = InMemoryMonitoringStore()
        domain = monitoring_store.upsert_domain("example.ru")
        job_store = InMemoryJobStore()
        guard = TargetScanGuard(active_ttl_seconds=60, cooldown_seconds=0)
        guard.reserve("example.ru", 443, "active-job")
        queued = []

        with patch(
            "shared.tls_audit.monitoring_scheduler.validate_target",
        ) as validate_target:
            validate_target.return_value.host = "example.ru"
            validate_target.return_value.port = 443
            validate_target.return_value.addresses = ["93.184.216.34"]

            result = schedule_due_scans(
                monitoring_store,
                job_store,
                queued.append,
                target_scan_guard=guard,
            )

        self.assertEqual(result.queued, [])
        self.assertEqual(result.skipped[0]["reason"], "active")
        self.assertEqual(result.skipped[0]["existing_job_id"], "active-job")
        self.assertEqual(queued, [])
        self.assertEqual(job_store.jobs, {})
        self.assertEqual(monitoring_store.due_domains()[0].id, domain.id)

    def test_scheduler_reports_enqueue_failure_and_releases_guard(self) -> None:
        monitoring_store = InMemoryMonitoringStore()
        monitoring_store.upsert_domain("example.ru")
        job_store = InMemoryJobStore()
        guard = TargetScanGuard(active_ttl_seconds=60, cooldown_seconds=0)

        def fail_enqueue(_payload):
            raise RuntimeError("queue down")

        with patch(
            "shared.tls_audit.monitoring_scheduler.validate_target",
        ) as validate_target:
            validate_target.return_value.host = "example.ru"
            validate_target.return_value.port = 443
            validate_target.return_value.addresses = ["93.184.216.34"]

            result = schedule_due_scans(
                monitoring_store,
                job_store,
                fail_enqueue,
                target_scan_guard=guard,
            )

        self.assertEqual(result.queued, [])
        self.assertEqual(result.skipped[0]["reason"], "enqueue_failed")
        self.assertEqual(job_store.jobs, {})
        decision = guard.reserve("example.ru", 443, "second-job")
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()

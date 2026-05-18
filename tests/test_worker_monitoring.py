import unittest
from unittest.mock import patch

from shared.tls_audit.jobs import InMemoryJobStore
from shared.tls_audit.monitoring_store import InMemoryMonitoringStore
from services.worker import worker


class WorkerMonitoringTests(unittest.TestCase):
    def test_handle_job_records_monitoring_snapshot_for_scheduled_scan(self) -> None:
        job_store = InMemoryJobStore()
        monitoring_store = InMemoryMonitoringStore()
        domain = monitoring_store.upsert_domain("example.ru")
        job = job_store.create("example.ru", 443, ["93.184.216.34"])

        with patch.object(worker, "job_store", job_store), patch.object(
            worker, "archive_store"
        ) as archive_store, patch.object(
            worker, "monitoring_store", monitoring_store
        ), patch.object(
            worker, "log_event"
        ), patch.object(
            worker, "validate_worker_target"
        ) as validate_worker_target, patch.object(
            worker, "run_full_scan"
        ) as run_full_scan, patch.object(
            worker, "release_target"
        ):
            validate_worker_target.return_value.host = "example.ru"
            validate_worker_target.return_value.port = 443
            validate_worker_target.return_value.addresses = ["93.184.216.34"]
            run_full_scan.return_value.to_dict.return_value = {
                "host": "example.ru",
                "port": 443,
                "grade": "A",
                "score": 95,
                "findings": [],
            }

            result = worker.handle_job(
                {
                    "id": job.id,
                    "host": "example.ru",
                    "port": 443,
                    "addresses": ["93.184.216.34"],
                    "monitored_domain_id": domain.id,
                    "trigger": "scheduled",
                }
            )

        self.assertEqual(result["status"], "done")
        self.assertEqual(monitoring_store.latest_snapshot(domain.id).scan_id, job.id)
        archive_store.save_report.assert_called()

    def test_handle_job_records_monitoring_failure_for_scheduled_scan(self) -> None:
        job_store = InMemoryJobStore()
        monitoring_store = InMemoryMonitoringStore()
        domain = monitoring_store.upsert_domain("example.ru")
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
                    "monitored_domain_id": domain.id,
                }
            )

        self.assertEqual(result["status"], "error")
        self.assertEqual(monitoring_store.events[0]["event_type"], "scan_failed")
        self.assertEqual(monitoring_store.events[0]["scan_id"], job.id)


if __name__ == "__main__":
    unittest.main()

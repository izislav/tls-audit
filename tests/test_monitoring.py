import unittest

from shared.tls_audit.monitoring import (
    MonitoringEvent,
    MonitoringSnapshot,
    diff_snapshots,
    events_from_diff,
    scan_failed_event,
    snapshot_from_report,
)
from shared.tls_audit.monitoring_pipeline import (
    record_monitoring_failure,
    record_monitoring_report,
)
from shared.tls_audit.monitoring_store import (
    InMemoryMonitoringStore,
    MIN_SCAN_INTERVAL_SECONDS,
    create_monitoring_store,
)


class MonitoringSnapshotTests(unittest.TestCase):
    def test_snapshot_from_report_extracts_operational_fields(self) -> None:
        snapshot = snapshot_from_report(
            7,
            "scan-1",
            {
                "grade": "A",
                "score": 95,
                "certificate": {
                    "not_after": "2026-07-01T00:00:00Z",
                    "expires_in_days": 44,
                },
                "protocols": {
                    "items": [
                        {"version": "TLS 1.3", "supported": True},
                        {"version": "TLS 1.2", "supported": True},
                        {"version": "TLS 1.1", "supported": False},
                    ]
                },
                "hsts": {
                    "hsts": "max-age=31536000",
                    "hsts_max_age": 31536000,
                    "hsts_include_subdomains": True,
                    "hsts_preload": False,
                },
                "findings": [
                    {
                        "code": "hsts_preload_missing",
                        "title": "HSTS preload не включен",
                        "severity": "info",
                        "category": "headers",
                    }
                ],
            },
        )

        self.assertEqual(snapshot.monitored_domain_id, 7)
        self.assertEqual(snapshot.scan_id, "scan-1")
        self.assertEqual(snapshot.grade, "A")
        self.assertEqual(snapshot.score, 95)
        self.assertEqual(snapshot.supported_protocols, ["TLS 1.2", "TLS 1.3"])
        self.assertTrue(snapshot.hsts["enabled"])
        self.assertEqual(snapshot.findings[0].code, "hsts_preload_missing")


class MonitoringDiffTests(unittest.TestCase):
    def test_diff_detects_degradation_and_added_high_finding(self) -> None:
        previous = MonitoringSnapshot(
            monitored_domain_id=1,
            scan_id="old",
            grade="A",
            score=96,
            certificate_expires_in_days=45,
            supported_protocols=["TLS 1.2", "TLS 1.3"],
            hsts={"enabled": True, "max_age": 31536000},
            findings=[],
        )
        current = snapshot_from_report(
            1,
            "new",
            {
                "grade": "B",
                "score": 84,
                "certificate": {"expires_in_days": 19},
                "protocols": {
                    "items": [
                        {"version": "TLS 1.0", "supported": True},
                        {"version": "TLS 1.2", "supported": True},
                    ]
                },
                "hsts": {"hsts": "", "hsts_max_age": None},
                "findings": [
                    {
                        "code": "legacy_tls",
                        "title": "Включён устаревший TLS",
                        "severity": "high",
                        "category": "tls",
                    }
                ],
            },
        )

        diff = diff_snapshots(current, previous)
        events = events_from_diff(diff)
        event_types = [event.event_type for event in events]

        self.assertTrue(diff.grade_degraded)
        self.assertEqual(diff.score_delta, -12)
        self.assertTrue(diff.certificate_expiring)
        self.assertEqual(diff.supported_protocols_added, ["TLS 1.0"])
        self.assertEqual(diff.supported_protocols_removed, ["TLS 1.3"])
        self.assertTrue(diff.hsts_changed)
        self.assertEqual(diff.added_findings[0].code, "legacy_tls")
        self.assertIn("grade_degraded", event_types)
        self.assertIn("certificate_expiring", event_types)
        self.assertIn("high_added", event_types)
        self.assertIn("legacy_tls_enabled", event_types)
        self.assertIn("hsts_changed", event_types)

    def test_diff_detects_resolved_serious_finding(self) -> None:
        previous = snapshot_from_report(
            1,
            "old",
            {
                "grade": "C",
                "score": 70,
                "findings": [
                    {
                        "code": "weak_cipher_3des",
                        "title": "Сервер принимает 3DES",
                        "severity": "high",
                        "category": "cipher",
                    }
                ],
            },
        )
        current = snapshot_from_report(1, "new", {"grade": "A", "score": 95, "findings": []})

        diff = diff_snapshots(current, previous)
        events = events_from_diff(diff)

        self.assertTrue(diff.grade_improved)
        self.assertEqual(diff.resolved_findings[0].code, "weak_cipher_3des")
        self.assertIn("finding_resolved", [event.event_type for event in events])

    def test_first_snapshot_marks_current_findings_as_added(self) -> None:
        current = snapshot_from_report(
            1,
            "first",
            {
                "certificate": {"expires_in_days": -1},
                "findings": [
                    {
                        "code": "certificate_expired",
                        "title": "Сертификат истёк",
                        "severity": "critical",
                        "category": "certificate",
                    }
                ],
            },
        )

        diff = diff_snapshots(current, None)
        events = events_from_diff(diff)

        self.assertTrue(diff.certificate_expired)
        self.assertEqual(diff.added_findings[0].severity, "critical")
        self.assertIn("certificate_expired", [event.event_type for event in events])
        self.assertIn("critical_added", [event.event_type for event in events])

    def test_scan_failed_event_is_critical_severity(self) -> None:
        event = scan_failed_event("timeout")

        self.assertEqual(event.event_type, "scan_failed")
        self.assertEqual(event.severity, "critical")
        self.assertEqual(event.detail, "timeout")


class MonitoringStoreTests(unittest.TestCase):
    def test_null_store_is_default_without_database_url(self) -> None:
        store = create_monitoring_store("")

        self.assertFalse(store.enabled)
        self.assertEqual(store.due_domains(), [])

    def test_in_memory_store_tracks_due_domains_and_schedule(self) -> None:
        store = InMemoryMonitoringStore()
        domain = store.upsert_domain("example.ru", scan_interval_seconds=60)

        self.assertEqual(store.due_domains()[0].host, "example.ru")
        self.assertEqual(domain.scan_interval_seconds, MIN_SCAN_INTERVAL_SECONDS)

        store.mark_scan_scheduled(domain.id, "scan-1")

        self.assertEqual(store.due_domains(), [])
        self.assertIsNotNone(store.domains[domain.id].last_scan_at)
        self.assertIsNotNone(store.domains[domain.id].next_scan_at)

    def test_in_memory_store_ignores_disabled_domains(self) -> None:
        store = InMemoryMonitoringStore()
        store.upsert_domain("example.ru", enabled=False)

        self.assertEqual(store.due_domains(), [])

    def test_in_memory_store_saves_snapshot_and_events(self) -> None:
        store = InMemoryMonitoringStore()
        domain = store.upsert_domain("example.ru")
        snapshot = store.save_snapshot(
            MonitoringSnapshot(
                monitored_domain_id=domain.id,
                scan_id="scan-1",
                grade="A",
                score=95,
            )
        )
        events = [
            MonitoringEvent(
                event_type="grade_improved",
                severity="info",
                title="Оценка улучшилась",
            )
        ]

        store.save_events(domain.id, snapshot.id, snapshot.scan_id, events)

        self.assertEqual(store.latest_snapshot(domain.id).scan_id, "scan-1")
        self.assertEqual(snapshot.id, 1)
        self.assertEqual(store.events[0]["event_type"], "grade_improved")
        self.assertEqual(store.list_domains()[0].id, domain.id)
        self.assertEqual(store.list_snapshots(domain.id)[0].scan_id, "scan-1")
        self.assertEqual(store.list_events(domain.id)[0]["event_type"], "grade_improved")


class MonitoringPipelineTests(unittest.TestCase):
    def test_record_monitoring_report_creates_snapshot_diff_and_events(self) -> None:
        store = InMemoryMonitoringStore()
        domain = store.upsert_domain("example.ru")
        record_monitoring_report(
            store,
            domain.id,
            "scan-1",
            {
                "grade": "A",
                "score": 95,
                "findings": [],
            },
        )

        snapshot, diff, events = record_monitoring_report(
            store,
            domain.id,
            "scan-2",
            {
                "grade": "B",
                "score": 82,
                "certificate": {"expires_in_days": 12},
                "findings": [
                    {
                        "code": "legacy_tls",
                        "title": "Включён устаревший TLS",
                        "severity": "high",
                        "category": "tls",
                    }
                ],
            },
        )

        self.assertEqual(snapshot.id, 2)
        self.assertTrue(diff.grade_degraded)
        self.assertIn("grade_degraded", [event.event_type for event in events])
        self.assertIn("high_added", [event.event_type for event in events])
        self.assertEqual(len(store.events), len(events))

    def test_record_monitoring_failure_ignores_non_monitoring_scan(self) -> None:
        store = InMemoryMonitoringStore()

        events = record_monitoring_failure(store, None, "scan-1", "timeout")

        self.assertEqual(events, [])
        self.assertEqual(store.events, [])

    def test_record_monitoring_failure_saves_event(self) -> None:
        store = InMemoryMonitoringStore()
        domain = store.upsert_domain("example.ru")

        events = record_monitoring_failure(store, domain.id, "scan-1", "timeout")

        self.assertEqual(events[0].event_type, "scan_failed")
        self.assertEqual(store.events[0]["scan_id"], "scan-1")


if __name__ == "__main__":
    unittest.main()

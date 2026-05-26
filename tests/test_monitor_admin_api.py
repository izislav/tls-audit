import unittest

try:
    from fastapi.testclient import TestClient
    from services.api.app import main
    from shared.tls_audit.monitoring_store import InMemoryMonitoringStore
except ModuleNotFoundError:
    TestClient = None
    main = None
    InMemoryMonitoringStore = None


@unittest.skipUnless(TestClient and main and InMemoryMonitoringStore, "fastapi test dependencies are unavailable")
class MonitorAdminApiAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(main.app)
        self.original_token = main.settings.monitoring_admin_token
        self.original_store = main.monitoring_store
        main.settings.monitoring_admin_token = "admin-secret"
        main.monitoring_store = InMemoryMonitoringStore()

    def tearDown(self) -> None:
        main.settings.monitoring_admin_token = self.original_token
        main.monitoring_store = self.original_store

    def test_monitor_domains_requires_admin_token(self) -> None:
        response = self.client.get("/api/monitor/domains")
        self.assertEqual(response.status_code, 404)

    def test_monitor_domains_rejects_wrong_admin_token(self) -> None:
        response = self.client.get(
            "/api/monitor/domains",
            headers={"x-monitoring-admin-token": "wrong"},
        )
        self.assertEqual(response.status_code, 404)

    def test_monitor_domains_allows_valid_admin_token(self) -> None:
        response = self.client.get(
            "/api/monitor/domains",
            headers={"x-monitoring-admin-token": "admin-secret"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("items", payload)

    def test_monitor_events_requires_admin_token(self) -> None:
        response = self.client.get("/api/monitor/domains/1/events")
        self.assertEqual(response.status_code, 404)

    def test_monitor_events_allows_valid_admin_token(self) -> None:
        response = self.client.get(
            "/api/monitor/domains/1/events",
            headers={"x-monitoring-admin-token": "admin-secret"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("items", payload)


if __name__ == "__main__":
    unittest.main()

import unittest

try:
    from fastapi.testclient import TestClient
    from services.api.app import main
    from shared.tls_audit.jobs import InMemoryJobStore
    from shared.tls_audit.report_export import report_digest_payload, report_digest_to_csv
except ModuleNotFoundError:
    TestClient = None
    main = None
    InMemoryJobStore = None
    report_digest_payload = None
    report_digest_to_csv = None


class _FakeArchiveStore:
    enabled = True

    def __init__(self, report: dict, scan: dict) -> None:
        self._report = report
        self._scan = scan

    def get_report(self, scan_id: str):  # noqa: ARG002
        return self._report

    def get_scan(self, scan_id: str):  # noqa: ARG002
        return self._scan

    def get_previous_report(self, scan_id: str):  # noqa: ARG002
        return None


@unittest.skipUnless(TestClient and main and InMemoryJobStore and report_digest_payload and report_digest_to_csv, "fastapi test dependencies are unavailable")
class ReportExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(main.app)
        self.original_archive_store = main.archive_store
        self.original_job_store = main.job_store
        self.original_public_base_url = main.settings.public_base_url

        self.report = {
            "host": "example.ru",
            "port": 443,
            "grade": "B",
            "score": 72,
            "summary": ["Сервер поддерживает устаревшие cipher suites."],
            "certificate": {
                "subject": "CN=example.ru",
                "issuer": "Test CA",
                "expires_in_days": 91,
                "not_after": "2026-09-01T00:00:00+00:00",
            },
            "hsts": {"hsts": "max-age=31536000", "hsts_max_age": 31536000, "hsts_include_subdomains": True, "hsts_preload": False},
            "findings": [
                {"code": "weak_cipher", "title": "Сервер принимает слабый cipher suite", "severity": "medium", "category": "cipher"},
                {"code": "hsts_missing", "title": "Нет заголовка HSTS", "severity": "medium", "category": "headers"},
            ],
            "recommendations": [
                {"title": "TLS 1.0 включён", "risk": "legacy", "fix": "Оставить только TLS 1.2/1.3"},
            ],
        }
        self.scan = {
            "id": "scan-1",
            "host": "example.ru",
            "port": 443,
            "grade": "B",
            "score": 72,
            "created_at": "2026-06-10T10:00:00+00:00",
            "finished_at": "2026-06-10T10:01:00+00:00",
        }
        main.archive_store = _FakeArchiveStore(self.report, self.scan)
        main.job_store = InMemoryJobStore()
        main.settings.public_base_url = "https://tlsaudit.ru"

    def tearDown(self) -> None:
        main.archive_store = self.original_archive_store
        main.job_store = self.original_job_store
        main.settings.public_base_url = self.original_public_base_url

    def test_report_digest_payload_is_compact(self) -> None:
        digest = report_digest_payload("scan-1", self.report, self.scan, "https://tlsaudit.ru")

        self.assertEqual(digest["host"], "example.ru")
        self.assertIn("severity_counts", digest)
        self.assertIn("links", digest)
        self.assertNotIn("findings", digest)
        self.assertIn("/api/report/scan-1/export.csv", digest["links"]["csv"])

    def test_report_export_csv_contains_digest_fields(self) -> None:
        csv_text = report_digest_to_csv("scan-1", self.report, self.scan, "https://tlsaudit.ru")

        self.assertIn("host,port,grade,score", csv_text)
        self.assertIn("example.ru,443,B,72", csv_text)
        self.assertIn("Сервер принимает слабый cipher suite", csv_text)

    def test_report_digest_endpoint_returns_compact_json(self) -> None:
        response = self.client.get("/api/report/scan-1/digest")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["host"], "example.ru")
        self.assertIn("severity_counts", payload)
        self.assertIn("links", payload)

    def test_report_export_csv_endpoint_returns_attachment(self) -> None:
        response = self.client.get("/api/report/scan-1/export.csv")

        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers["content-type"])
        self.assertIn("attachment", response.headers["content-disposition"])
        self.assertIn("example.ru", response.text)


if __name__ == "__main__":
    unittest.main()

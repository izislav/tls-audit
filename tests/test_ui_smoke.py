import unittest

try:
    from fastapi.testclient import TestClient
    from services.api.app.main import app
except ModuleNotFoundError:
    TestClient = None
    app = None


@unittest.skipUnless(TestClient and app, "fastapi test dependencies are unavailable")
class UiSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_homepage_renders(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("TLS Audit", response.text)

    def test_scan_page_renders(self) -> None:
        response = self.client.get("/scan?job=smoke")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Готов к первой проверке", response.text)

    def test_monitor_status_page_renders(self) -> None:
        response = self.client.get("/monitor-status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Magic link по email", response.text)
        self.assertIn("Отправить ссылку", response.text)


if __name__ == "__main__":
    unittest.main()

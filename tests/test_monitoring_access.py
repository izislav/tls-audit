import unittest
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
    from services.api.app import main
    from shared.tls_audit.subscription_store import InMemorySubscriptionStore
except ModuleNotFoundError:
    TestClient = None
    main = None
    InMemorySubscriptionStore = None

from shared.tls_audit.monitor_access import (
    build_monitor_token_secret,
    create_monitor_owner_token,
    email_from_monitor_owner_token,
    monitoring_admin_token_valid,
)


class MonitoringAccessTests(unittest.TestCase):
    def test_owner_token_roundtrip(self) -> None:
        secret = "secret-1"
        token = create_monitor_owner_token("Admin@Example.RU", secret)

        self.assertEqual(
            email_from_monitor_owner_token(token, secret),
            "admin@example.ru",
        )

    def test_owner_token_rejects_invalid_value(self) -> None:
        self.assertIsNone(email_from_monitor_owner_token("broken-token", "secret-1"))

    def test_owner_token_rejects_wrong_secret(self) -> None:
        token = create_monitor_owner_token("admin@example.ru", "secret-1")

        self.assertIsNone(email_from_monitor_owner_token(token, "secret-2"))

    def test_owner_token_expires(self) -> None:
        token = create_monitor_owner_token(
            "admin@example.ru",
            "secret-1",
            issued_at=1_000,
        )

        self.assertEqual(
            email_from_monitor_owner_token(
                token,
                "secret-1",
                max_age_seconds=60,
                now=1_059,
            ),
            "admin@example.ru",
        )
        self.assertIsNone(
            email_from_monitor_owner_token(
                token,
                "secret-1",
                max_age_seconds=60,
                now=1_061,
            )
        )

    def test_monitor_secret_falls_back_to_environment_shape(self) -> None:
        secret = build_monitor_token_secret(
            monitoring_token_secret="",
            database_url="postgres://db",
            redis_url="redis://cache",
            public_base_url="https://tlsaudit.ru",
            contact_email="info@tlsaudit.ru",
        )

        self.assertIn("postgres://db", secret)
        self.assertIn("redis://cache", secret)
        self.assertIn("tls-audit-monitoring-v1", secret)

    def test_monitoring_admin_token_validation(self) -> None:
        self.assertTrue(monitoring_admin_token_valid("secret", "secret"))
        self.assertFalse(monitoring_admin_token_valid("secret", "other"))
        self.assertFalse(monitoring_admin_token_valid("", "secret"))


@unittest.skipUnless(TestClient and main and InMemorySubscriptionStore, "fastapi test dependencies are unavailable")
class MonitorMagicLinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(main.app)
        self.original_subscription_store = main.subscription_store
        self.original_send_email = main.send_email
        self.original_public_base_url = main.settings.public_base_url
        self.original_smtp_url = main.os.environ.get("SMTP_URL")
        main.subscription_store = InMemorySubscriptionStore()
        main.subscription_store.upsert_pending(
            host="nrdrive.ru",
            port=443,
            email="y.fedorov@nrdrive.ru",
            plan="support",
        )
        main.settings.public_base_url = "https://tlsaudit.ru"
        main.os.environ["SMTP_URL"] = "smtp://example"
        self.sent_messages = []

        def fake_send_email(**kwargs):
            self.sent_messages.append(kwargs)
            return True

        main.send_email = fake_send_email

    def tearDown(self) -> None:
        main.subscription_store = self.original_subscription_store
        main.send_email = self.original_send_email
        main.settings.public_base_url = self.original_public_base_url
        if self.original_smtp_url is None:
            main.os.environ.pop("SMTP_URL", None)
        else:
            main.os.environ["SMTP_URL"] = self.original_smtp_url

    def test_magic_link_endpoint_sends_email(self) -> None:
        response = self.client.post(
            "/api/subscriptions/monitoring/magic-link",
            json={"email": "y.fedorov@nrdrive.ru"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "accepted")
        self.assertTrue(self.sent_messages)
        message = self.sent_messages[0]
        self.assertEqual(message["mail_to"], "y.fedorov@nrdrive.ru")
        self.assertIn("/monitor-status?token=", message["body"])

    def test_owner_token_can_delete_subscription(self) -> None:
        sub = main.subscription_store.upsert_pending(
            host="delete-me.ru",
            port=443,
            email="y.fedorov@nrdrive.ru",
            plan="support",
        )
        token = main.create_monitor_owner_token("y.fedorov@nrdrive.ru")

        response = self.client.delete(
            f"/api/subscriptions/monitoring/{sub.id}",
            params={"token": token},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "disabled")
        self.assertFalse(main.subscription_store.get_by_id(sub.id).enabled)

    def test_subscription_response_does_not_expose_confirmation_secrets(self) -> None:
        with patch.object(main, "validate_target") as validate_target:
            validate_target.return_value.host = "example.ru"
            validate_target.return_value.port = 443
            validate_target.return_value.addresses = ["93.184.216.34"]
            response = self.client.post(
                "/api/subscriptions/monitoring",
                json={
                    "host": "example.ru",
                    "email": "new@example.ru",
                    "plan": "free",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "pending_confirmation")
        self.assertNotIn("confirm_url", payload)
        self.assertNotIn("unsubscribe_url", payload)

    def test_http_ownership_rejects_localhost_before_connecting(self) -> None:
        ok, detail = main.verify_http_file("localhost", "challenge")

        self.assertFalse(ok)
        self.assertIn("отклонена", detail)


if __name__ == "__main__":
    unittest.main()

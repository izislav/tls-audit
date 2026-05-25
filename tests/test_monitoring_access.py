import unittest

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


if __name__ == "__main__":
    unittest.main()

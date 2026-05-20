import unittest

from shared.tls_audit.billing_store import InMemoryBillingStore


class BillingStoreTests(unittest.TestCase):
    def test_checkout_then_activate_pro(self) -> None:
        store = InMemoryBillingStore()

        pending = store.create_checkout("Admin@Example.ru", "pro_1")
        self.assertEqual(pending.email, "admin@example.ru")
        self.assertEqual(pending.status, "pending")
        self.assertEqual(pending.checkout_id, "pro_1")

        active = store.activate_pro("Admin@Example.ru")
        self.assertEqual(active.plan, "support")
        self.assertEqual(active.status, "active")
        self.assertEqual(active.domain_limit, 10)

        loaded = store.get_by_email("admin@example.ru")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.status, "active")


if __name__ == "__main__":
    unittest.main()

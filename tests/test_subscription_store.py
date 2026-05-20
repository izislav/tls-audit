import unittest
from datetime import timedelta

from shared.tls_audit.subscription_store import InMemorySubscriptionStore
from shared.tls_audit.subscription_store import utcnow


class SubscriptionStoreTests(unittest.TestCase):
    def test_list_by_email_returns_newest_first(self) -> None:
        store = InMemorySubscriptionStore()
        store.upsert_pending("one.example", 443, "user@example.ru", plan="free")
        store.items[1].enabled = False
        store.upsert_pending("two.example", 443, "user@example.ru", plan="support")

        items = store.list_by_email("user@example.ru")

        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].host, "two.example")
        self.assertEqual(items[1].host, "one.example")

    def test_alert_cooldown_in_memory(self) -> None:
        store = InMemorySubscriptionStore()
        sub = store.upsert_pending("one.example", 443, "user@example.ru", plan="support")
        now = utcnow()
        self.assertTrue(store.should_send_alert(sub.id, "scan_failed", 86400, now=now))
        store.mark_alert_sent(sub.id, "scan_failed", when=now)
        self.assertFalse(store.should_send_alert(sub.id, "scan_failed", 86400, now=now + timedelta(hours=1)))
        self.assertTrue(store.should_send_alert(sub.id, "scan_failed", 86400, now=now + timedelta(days=1, seconds=1)))


if __name__ == "__main__":
    unittest.main()

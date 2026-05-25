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

    def test_report_delivery_dedup_in_memory(self) -> None:
        store = InMemorySubscriptionStore()
        sub = store.upsert_pending("one.example", 443, "user@example.ru", plan="support")
        self.assertTrue(store.should_send_report(sub.id, "scan-1"))
        store.mark_report_sent(sub.id, "scan-1")
        self.assertFalse(store.should_send_report(sub.id, "scan-1"))
        self.assertTrue(store.should_send_report(sub.id, "scan-2"))

    def test_same_email_can_have_multiple_domains(self) -> None:
        store = InMemorySubscriptionStore()
        first = store.upsert_pending("one.example", 443, "user@example.ru", plan="support")
        second = store.upsert_pending("two.example", 443, "user@example.ru", plan="support")

        self.assertNotEqual(first.id, second.id)
        items = store.list_by_email("user@example.ru")
        self.assertEqual(len(items), 2)

    def test_support_due_requires_ownership_verification(self) -> None:
        store = InMemorySubscriptionStore()
        free_sub = store.upsert_pending("free.example", 443, "user@example.ru", plan="free")
        free_sub.confirmed = True
        free_sub.next_run_at = utcnow() - timedelta(seconds=1)

        support_sub = store.upsert_pending("pro.example", 443, "user@example.ru", plan="support")
        support_sub.confirmed = True
        support_sub.next_run_at = utcnow() - timedelta(seconds=1)

        due = store.due()
        due_ids = {item.id for item in due}
        self.assertIn(free_sub.id, due_ids)
        self.assertNotIn(support_sub.id, due_ids)

        store.mark_ownership_verified(support_sub.id)
        due_after = store.due()
        due_after_ids = {item.id for item in due_after}
        self.assertIn(support_sub.id, due_after_ids)


if __name__ == "__main__":
    unittest.main()

import unittest
from datetime import datetime, timedelta, timezone

from shared.tls_audit.subscription_store import InMemorySubscriptionStore
from shared.tls_audit.subscription_store import next_weekly_report_at, utcnow


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

    def test_support_reuses_verified_ownership_for_same_domain_and_email(self) -> None:
        store = InMemorySubscriptionStore()
        first = store.upsert_pending("one.example", 443, "user@example.ru", plan="support")
        first.confirmed = True
        store.mark_ownership_verified(first.id)

        second = store.upsert_pending("one.example", 443, "user@example.ru", plan="support")
        self.assertEqual(first.id, second.id)
        self.assertIsNotNone(second.ownership_verified_at)
        self.assertEqual(second.ownership_method, "trusted_reuse")

    def test_confirmation_link_expires(self) -> None:
        store = InMemorySubscriptionStore()
        sub = store.upsert_pending("one.example", 443, "user@example.ru")
        sub.updated_at = utcnow() - timedelta(hours=25)

        self.assertIsNone(store.confirm(sub.token, max_age_seconds=86400))

    def test_cleanup_removes_only_stale_unconfirmed_subscriptions(self) -> None:
        store = InMemorySubscriptionStore()
        stale = store.upsert_pending("old.example", 443, "user@example.ru")
        stale.updated_at = utcnow() - timedelta(hours=49)
        active = store.upsert_pending("active.example", 443, "user@example.ru")
        active.confirmed = True
        active.updated_at = utcnow() - timedelta(hours=49)

        self.assertEqual(store.cleanup_unconfirmed(max_age_hours=48), 1)
        self.assertIsNone(store.get_by_id(stale.id))
        self.assertIsNotNone(store.get_by_id(active.id))

    def test_next_weekly_report_at_pins_to_monday_five_moscow(self) -> None:
        reference = datetime(2026, 6, 4, 12, 0, tzinfo=timezone.utc)  # Thursday
        scheduled = next_weekly_report_at(reference)

        self.assertEqual(scheduled.weekday(), 0)
        self.assertEqual(scheduled.astimezone(timezone(timedelta(hours=3))).hour, 5)
        self.assertEqual(scheduled.astimezone(timezone(timedelta(hours=3))).minute, 0)

    def test_next_weekly_report_at_moves_forward_when_monday_window_passed(self) -> None:
        reference = datetime(2026, 6, 1, 3, 10, tzinfo=timezone.utc)  # Monday 06:10 Moscow
        scheduled = next_weekly_report_at(reference)

        local = scheduled.astimezone(timezone(timedelta(hours=3)))
        self.assertEqual(local.weekday(), 0)
        self.assertEqual(local.hour, 5)
        self.assertEqual(local.day, 8)


if __name__ == "__main__":
    unittest.main()

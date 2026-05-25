import unittest
from unittest.mock import patch

from shared.tls_audit.subscription_store import MonitorSubscription


class SubscriptionSchedulerTests(unittest.TestCase):
    def _due_sub(self) -> MonitorSubscription:
        return MonitorSubscription(
            id=1,
            host="example.ru",
            port=443,
            email="admin@example.ru",
            token="t",
            enabled=True,
            confirmed=True,
        )

    def test_process_subscriptions_enqueues_with_subscription_payload(self) -> None:
        from services.scheduler import scheduler

        due = [self._due_sub()]
        with patch.object(scheduler.subscription_store, "due", return_value=due):
            with patch.object(scheduler.monitoring_store, "upsert_domain", return_value=object()):
                with patch.object(
                    scheduler,
                    "schedule_domain_scan",
                    return_value=type("S", (), {"job_id": "job-1"})(),
                ) as schedule:
                    scheduler.process_subscriptions(limit=10)
        payload = schedule.call_args.kwargs["payload_extra"]
        self.assertEqual(payload["subscription_id"], 1)
        self.assertEqual(payload["subscription_email"], "admin@example.ru")


if __name__ == "__main__":
    unittest.main()

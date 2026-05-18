import unittest
from unittest.mock import Mock, patch

from shared.tls_audit.monitoring_scheduler import SchedulerResult


class MonitoringSchedulerLoopTests(unittest.TestCase):
    def test_positive_int_uses_default_for_invalid_values(self) -> None:
        from services.scheduler.scheduler import positive_int

        self.assertEqual(positive_int(None, 60), 60)
        self.assertEqual(positive_int("", 60), 60)
        self.assertEqual(positive_int("nope", 60), 60)
        self.assertEqual(positive_int("0", 60), 60)
        self.assertEqual(positive_int("15", 60), 15)

    def test_run_once_schedules_due_domains_and_logs_tick(self) -> None:
        from services.scheduler import scheduler

        expected = SchedulerResult()
        expected.skipped.append({"domain_id": 1, "reason": "validation_failed"})

        with patch.object(scheduler, "schedule_due_scans", return_value=expected) as schedule:
            with patch.object(scheduler, "log_event") as log_event:
                result = scheduler.run_once(limit=7)

        self.assertIs(result, expected)
        self.assertEqual(schedule.call_args.kwargs["limit"], 7)
        log_event.assert_called_once()
        self.assertEqual(log_event.call_args.args[1], "monitor_scheduler_tick")
        self.assertEqual(log_event.call_args.kwargs["queued"], 0)
        self.assertEqual(log_event.call_args.kwargs["skipped"], 1)

    def test_run_loop_keeps_running_after_scheduler_error(self) -> None:
        from services.scheduler import scheduler

        sleep = Mock(side_effect=KeyboardInterrupt)
        with patch.object(scheduler, "run_once", side_effect=RuntimeError("boom")):
            with patch.object(scheduler, "log_event") as log_event:
                with self.assertRaises(KeyboardInterrupt):
                    scheduler.run_loop(poll_seconds=3, limit=5, sleep=sleep)

        sleep.assert_called_once_with(3)
        events = [call.args[1] for call in log_event.call_args_list]
        self.assertIn("monitor_scheduler_started", events)
        self.assertIn("monitor_scheduler_failed", events)


if __name__ == "__main__":
    unittest.main()

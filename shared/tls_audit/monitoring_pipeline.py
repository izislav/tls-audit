from typing import Dict, List, Optional, Tuple

from .monitoring import (
    MonitoringDiff,
    MonitoringEvent,
    MonitoringSnapshot,
    diff_snapshots,
    events_from_diff,
    scan_failed_events,
    snapshot_from_report,
)
from .monitoring_store import NullMonitoringStore


def record_monitoring_report(
    store: NullMonitoringStore,
    monitored_domain_id: int,
    scan_id: str,
    report: Dict[str, object],
) -> Tuple[MonitoringSnapshot, MonitoringDiff, List[MonitoringEvent]]:
    snapshot = snapshot_from_report(monitored_domain_id, scan_id, report)
    saved_snapshot = store.save_snapshot(snapshot)
    previous = store.latest_snapshot(
        monitored_domain_id,
        before_snapshot_id=saved_snapshot.id,
    )
    diff = diff_snapshots(saved_snapshot, previous)
    events = events_from_diff(diff)
    store.save_events(
        monitored_domain_id,
        saved_snapshot.id,
        saved_snapshot.scan_id,
        events,
    )
    return saved_snapshot, diff, events


def record_monitoring_failure(
    store: NullMonitoringStore,
    monitored_domain_id: Optional[int],
    scan_id: Optional[str],
    error: str,
) -> List[MonitoringEvent]:
    if not monitored_domain_id:
        return []
    events = scan_failed_events(error)
    store.save_events(monitored_domain_id, None, scan_id, events)
    return events

import csv
import io
from typing import Dict


def monitoring_export_to_csv(payload: Dict[str, object]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "subscription_id",
            "host",
            "port",
            "plan",
            "enabled",
            "confirmed",
            "ownership_verified",
            "last_sent_at",
            "next_run_at",
            "event_type",
            "event_severity",
            "event_title",
            "event_detail",
            "event_created_at",
        ]
    )
    for item in payload.get("items", []):
        if not isinstance(item, dict):
            continue
        base = [
            item.get("subscription_id"),
            item.get("host"),
            item.get("port"),
            item.get("plan"),
            item.get("enabled"),
            item.get("confirmed"),
            item.get("ownership_verified"),
            item.get("last_sent_at") or "",
            item.get("next_run_at") or "",
        ]
        events = item.get("events") or []
        if isinstance(events, list) and events:
            for event in events:
                if not isinstance(event, dict):
                    continue
                writer.writerow(
                    base
                    + [
                        event.get("event_type") or "",
                        event.get("severity") or "",
                        event.get("title") or "",
                        event.get("detail") or "",
                        event.get("created_at") or "",
                    ]
                )
        else:
            writer.writerow(base + ["", "", "", "", ""])
    return output.getvalue()

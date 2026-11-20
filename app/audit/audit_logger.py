
import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUDIT_LOG_PATH = PROJECT_ROOT / "logs" / "remediation_audit.jsonl"

logger = logging.getLogger("identity_commander.audit")

_write_lock = threading.Lock()


def _write_audit_event(event: dict, event_type: str) -> None:
    """Append an event to the audit log."""

    audit_record = {
        **event,
        "event_type": event_type,
        "recorded_at": datetime.now(UTC).isoformat(),
    }

    try:
        with _write_lock:
            AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

            with AUDIT_LOG_PATH.open("a", encoding="utf-8") as file:
                file.write(json.dumps(audit_record, default=str) + "\n")
    except OSError:
        logger.exception("Failed to write audit event.")
        raise


def read_audit_events() -> list[dict]:
    """Return all parseable audit events in recorded order."""

    if not AUDIT_LOG_PATH.exists():
        return []

    events = []

    with AUDIT_LOG_PATH.open(encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed audit log line.")
                continue

            if isinstance(event, dict):
                events.append(event)

    return events


def has_simulated_removal(role_assignment_id: str) -> bool:
    """Return True when a removal was already executed for the assignment."""

    target = role_assignment_id.rstrip("/").casefold()

    return any(
        event.get("action") == "ROLE_ASSIGNMENT_REMOVAL"
        and event.get("status") in ("EXECUTED", "SIMULATED")
        and str(event.get("role_assignment_id", "")).rstrip("/").casefold()
        == target
        for event in read_audit_events()
    )


def log_investigation_event(event: dict) -> None:
    """Record identity investigation events."""

    _write_audit_event(event, "INVESTIGATION")


def log_approval_event(event: dict) -> None:
    """Record approval creation and decision events."""

    _write_audit_event(event, "APPROVAL")


def log_remediation_event(event: dict) -> None:
    """Record simulated remediation events, including rejections."""

    _write_audit_event(event, "REMEDIATION")


def log_verification_event(event: dict) -> None:
    """Record remediation verification events."""

    _write_audit_event(event, "VERIFICATION")

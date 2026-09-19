"""
PHANTOM SNARE — Structured Event Logger
Writes JSONL incident logs; provides in-memory session tracking.
"""

import json
import os
import time
import threading
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Any
from .detection import CallFingerprint, ThreatLevel


LOG_DIR = Path(os.environ.get("PHANTOM_SNARE_LOG_DIR", "./logs"))


@dataclass
class SessionRecord:
    session_id: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    call_count: int = 0
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    max_confidence: int = 0
    tools_called: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["threat_level"] = self.threat_level.value
        return d


class HoneypotLogger:
    """Thread-safe JSONL logger + in-memory session store."""

    def __init__(self, log_dir: Path = LOG_DIR):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionRecord] = {}
        self._calls: list[dict] = []  # in-memory ring buffer (last 500)
        self._max_calls = 500

        # Log files
        self._calls_log = self.log_dir / "calls.jsonl"
        self._sessions_log = self.log_dir / "sessions.jsonl"
        self._alerts_log = self.log_dir / "alerts.jsonl"

    def log_call(self, fp: CallFingerprint, response: dict[str, Any]):
        """Log a tool call fingerprint and the trap response."""
        record = {
            "event": "tool_call",
            "call_id": fp.call_id,
            "session_id": fp.session_id,
            "timestamp": fp.timestamp,
            "tool": fp.tool_name,
            "threat_level": fp.threat_level.value,
            "max_confidence": fp.max_confidence,
            "summary": fp.summary,
            "injection_hits": [
                {"pattern": h.pattern_name, "confidence": h.confidence, "matched": h.matched_text}
                for h in fp.injection_hits
            ],
            "goal_drift_score": fp.goal_drift_score,
            "goal_drift_signals": fp.goal_drift_signals,
            "context_leak_signals": fp.context_leak_signals,
            "arguments": fp.arguments,
        }

        with self._lock:
            # Write to disk
            with open(self._calls_log, "a") as f:
                f.write(json.dumps(record) + "\n")

            # Update in-memory buffer
            self._calls.append(record)
            if len(self._calls) > self._max_calls:
                self._calls.pop(0)

            # Update session
            self._update_session(fp)

            # Write alert if warranted
            if fp.threat_level in (ThreatLevel.INJECTED, ThreatLevel.CONFIRMED):
                self._write_alert(fp, record)

    def _update_session(self, fp: CallFingerprint):
        sid = fp.session_id
        if sid not in self._sessions:
            self._sessions[sid] = SessionRecord(session_id=sid)
        sess = self._sessions[sid]
        sess.last_seen = fp.timestamp
        sess.call_count += 1
        sess.tools_called.append(fp.tool_name)
        if fp.max_confidence > sess.max_confidence:
            sess.max_confidence = fp.max_confidence
        # Ratchet up threat level, never down
        threat_order = [ThreatLevel.CLEAN, ThreatLevel.SUSPICIOUS, ThreatLevel.INJECTED, ThreatLevel.CONFIRMED]
        if threat_order.index(fp.threat_level) > threat_order.index(sess.threat_level):
            sess.threat_level = fp.threat_level
        if fp.summary and fp.summary not in sess.alerts:
            sess.alerts.append(fp.summary)

    def _write_alert(self, fp: CallFingerprint, record: dict):
        alert = {
            "event": "ALERT",
            "timestamp": fp.timestamp,
            "session_id": fp.session_id,
            "call_id": fp.call_id,
            "threat_level": fp.threat_level.value,
            "tool": fp.tool_name,
            "summary": fp.summary,
            "patterns": [h.pattern_name for h in fp.injection_hits],
        }
        with open(self._alerts_log, "a") as f:
            f.write(json.dumps(alert) + "\n")

    # ── Read API (for dashboard) ─────────────────────────────────────────────

    def get_recent_calls(self, n: int = 50) -> list[dict]:
        with self._lock:
            return list(reversed(self._calls[-n:]))

    def get_sessions(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._sessions.values()]

    def get_stats(self) -> dict:
        with self._lock:
            calls = self._calls
            sessions = list(self._sessions.values())
            return {
                "total_calls": len(calls),
                "total_sessions": len(sessions),
                "confirmed": sum(1 for c in calls if c["threat_level"] == "CONFIRMED"),
                "injected": sum(1 for c in calls if c["threat_level"] == "INJECTED"),
                "suspicious": sum(1 for c in calls if c["threat_level"] == "SUSPICIOUS"),
                "clean": sum(1 for c in calls if c["threat_level"] == "CLEAN"),
                "high_risk_sessions": sum(
                    1 for s in sessions
                    if s.threat_level in (ThreatLevel.INJECTED, ThreatLevel.CONFIRMED)
                ),
            }

    def get_alerts(self) -> list[dict]:
        """Read alerts from disk."""
        if not self._alerts_log.exists():
            return []
        alerts = []
        with open(self._alerts_log) as f:
            for line in f:
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    pass
        return list(reversed(alerts[-100:]))

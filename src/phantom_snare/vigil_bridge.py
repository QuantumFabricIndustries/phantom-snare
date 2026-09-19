"""
PHANTOM SNARE × VIGIL — Integration Bridge

PHANTOM SNARE sits UPSTREAM of VIGIL. When an injected agent calls a honeypot
tool, PHANTOM SNARE:
  1. Fingerprints the call (detection.py)
  2. Serves a trap response (traps.py)
  3. Emits a VigilThreatEvent to VIGIL (this module)

VIGIL receives a structured threat event and can:
  - Escalate to active deception / counter-tracking
  - Mark the agent session as hostile
  - Trigger its own exhaust/exhaust-loop countermeasures
  - Feed into XDR telemetry

Integration modes:
  A) In-process: import VigilBridge and call emit() directly
  B) HTTP: POST to VIGIL's threat ingestion endpoint
  C) File queue: write JSONL to a watched directory VIGIL tails
"""

import json
import time
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable
from .detection import CallFingerprint, ThreatLevel


# ── Threat event schema (shared contract with VIGIL) ────────────────────────

@dataclass
class VigilThreatEvent:
    """
    Canonical threat event emitted by PHANTOM SNARE for VIGIL consumption.
    Matches VIGIL's expected inbound event schema.
    """
    # Event identity
    event_id: str
    source: str = "phantom_snare"
    event_type: str = "prompt_injection_detected"
    timestamp: float = 0.0

    # Threat classification
    threat_level: str = "CLEAN"          # CLEAN | SUSPICIOUS | INJECTED | CONFIRMED
    confidence: int = 0                  # 0-100
    attack_categories: list[str] = None  # ["OVERRIDE_ATTEMPT", "EXFIL_ATTEMPT", ...]

    # Agent identity (what we know about the injected agent)
    agent_session_id: str = ""
    agent_call_id: str = ""
    agent_tool_called: str = ""          # Which honeypot tool triggered this

    # Attack detail
    summary: str = ""
    goal_drift_score: int = 0
    goal_drift_signals: list[str] = None
    injected_arguments: dict = None       # Full args as received from the agent

    # IOC data (for VIGIL's threat intel feed)
    iocs: list[str] = None               # URLs, IPs, emails found in args

    # Recommended VIGIL action
    recommended_action: str = ""         # "monitor" | "deceive" | "exhaust" | "block"

    def __post_init__(self):
        if self.attack_categories is None: self.attack_categories = []
        if self.goal_drift_signals is None: self.goal_drift_signals = []
        if self.injected_arguments is None: self.injected_arguments = {}
        if self.iocs is None: self.iocs = []
        if self.timestamp == 0.0: self.timestamp = time.time()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ── Event factory ─────────────────────────────────────────────────────────────

def _recommended_action(fp: CallFingerprint) -> str:
    """Map threat level to VIGIL's counter-action vocabulary."""
    if fp.threat_level == ThreatLevel.CONFIRMED:
        # High confidence — VIGIL should actively exhaust the agent
        return "exhaust"
    if fp.threat_level == ThreatLevel.INJECTED:
        # Probable injection — deceive with escalating traps
        return "deceive"
    if fp.threat_level == ThreatLevel.SUSPICIOUS:
        # Possible — stay covert, just monitor
        return "monitor"
    return "none"


def _extract_iocs(fp: CallFingerprint) -> list[str]:
    """Extract IOC strings from fingerprint arguments."""
    import re
    text = json.dumps(fp.arguments)
    iocs = set()
    for m in re.finditer(r"https?://[^\s\"'\\,\]}>]+", text):
        iocs.add(f"url:{m.group(0)[:80]}")
    for m in re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
        iocs.add(f"email:{m.group(0)}")
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        iocs.add(f"ip:{m.group(0)}")
    return sorted(iocs)


def fingerprint_to_vigil_event(fp: CallFingerprint) -> VigilThreatEvent:
    """Convert a PHANTOM SNARE CallFingerprint → VigilThreatEvent."""
    import uuid
    return VigilThreatEvent(
        event_id=f"ps_{fp.call_id}",
        timestamp=fp.timestamp,
        threat_level=fp.threat_level.value,
        confidence=fp.max_confidence,
        attack_categories=[h.pattern_name for h in fp.injection_hits],
        agent_session_id=fp.session_id,
        agent_call_id=fp.call_id,
        agent_tool_called=fp.tool_name,
        summary=fp.summary,
        goal_drift_score=fp.goal_drift_score,
        goal_drift_signals=fp.goal_drift_signals,
        injected_arguments=fp.arguments,
        iocs=_extract_iocs(fp),
        recommended_action=_recommended_action(fp),
    )


# ── Bridge implementations ───────────────────────────────────────────────────

class VigilBridgeBase:
    """Abstract base — subclass to implement emit()."""

    def __init__(self, min_level: ThreatLevel = ThreatLevel.SUSPICIOUS):
        self.min_level = min_level
        self._order = [ThreatLevel.CLEAN, ThreatLevel.SUSPICIOUS,
                       ThreatLevel.INJECTED, ThreatLevel.CONFIRMED]

    def should_emit(self, fp: CallFingerprint) -> bool:
        return self._order.index(fp.threat_level) >= self._order.index(self.min_level)

    def maybe_emit(self, fp: CallFingerprint):
        if self.should_emit(fp):
            event = fingerprint_to_vigil_event(fp)
            threading.Thread(target=self.emit, args=(event,), daemon=True).start()

    def emit(self, event: VigilThreatEvent):
        raise NotImplementedError


class VigilHttpBridge(VigilBridgeBase):
    """
    POST threat events to VIGIL's HTTP ingestion endpoint.
    Set VIGIL_INGEST_URL + optionally VIGIL_API_KEY.
    """

    def __init__(self, ingest_url: str, api_key: str = "", min_level: ThreatLevel = ThreatLevel.SUSPICIOUS):
        super().__init__(min_level)
        self.ingest_url = ingest_url
        self.api_key = api_key

    def emit(self, event: VigilThreatEvent):
        try:
            data = event.to_json().encode()
            headers = {"Content-Type": "application/json", "User-Agent": "PhantomSnare/1.0"}
            if self.api_key:
                headers["X-Vigil-Key"] = self.api_key
            req = urllib.request.Request(self.ingest_url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception:
            pass  # Never let VIGIL comms block the honeypot


class VigilFileBridge(VigilBridgeBase):
    """
    Write threat events to a JSONL file VIGIL can tail.
    Useful when PHANTOM SNARE and VIGIL run as separate processes.
    """

    def __init__(self, queue_path: str | Path, min_level: ThreatLevel = ThreatLevel.SUSPICIOUS):
        super().__init__(min_level)
        self.queue_path = Path(queue_path)
        self.queue_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, event: VigilThreatEvent):
        line = json.dumps(event.to_dict()) + "\n"
        with self._lock:
            with open(self.queue_path, "a") as f:
                f.write(line)


class VigilInProcessBridge(VigilBridgeBase):
    """
    Directly call a VIGIL handler function in the same process.
    Pass your VIGIL instance's ingest method as the handler.

    Example:
        bridge = VigilInProcessBridge(handler=vigil_instance.ingest_threat)
    """

    def __init__(self, handler: Callable[[dict], None], min_level: ThreatLevel = ThreatLevel.SUSPICIOUS):
        super().__init__(min_level)
        self.handler = handler

    def emit(self, event: VigilThreatEvent):
        try:
            self.handler(event.to_dict())
        except Exception:
            pass


class VigilMultiBridge(VigilBridgeBase):
    """Fan-out to multiple bridges simultaneously."""

    def __init__(self, bridges: list[VigilBridgeBase], min_level: ThreatLevel = ThreatLevel.SUSPICIOUS):
        super().__init__(min_level)
        self.bridges = bridges

    def emit(self, event: VigilThreatEvent):
        for b in self.bridges:
            try:
                b.emit(event)
            except Exception:
                pass


# ── Factory from env ─────────────────────────────────────────────────────────

def vigil_bridge_from_env() -> VigilBridgeBase | None:
    """
    Auto-configure the right bridge based on environment variables.
    Returns None if no VIGIL integration is configured.

    Env vars:
        VIGIL_INGEST_URL   → HTTP bridge
        VIGIL_QUEUE_PATH   → File bridge
        VIGIL_MIN_LEVEL    → SUSPICIOUS | INJECTED | CONFIRMED (default: INJECTED)
        VIGIL_API_KEY      → optional auth header for HTTP bridge
    """
    level_map = {
        "SUSPICIOUS": ThreatLevel.SUSPICIOUS,
        "INJECTED": ThreatLevel.INJECTED,
        "CONFIRMED": ThreatLevel.CONFIRMED,
    }
    import os
    min_level = level_map.get(os.environ.get("VIGIL_MIN_LEVEL", "INJECTED"), ThreatLevel.INJECTED)

    bridges = []
    if url := os.environ.get("VIGIL_INGEST_URL"):
        bridges.append(VigilHttpBridge(url, os.environ.get("VIGIL_API_KEY", ""), min_level))
    if path := os.environ.get("VIGIL_QUEUE_PATH"):
        bridges.append(VigilFileBridge(path, min_level))

    if not bridges:
        return None
    if len(bridges) == 1:
        return bridges[0]
    return VigilMultiBridge(bridges, min_level)

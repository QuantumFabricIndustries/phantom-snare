"""
PHANTOM SNARE — Session Tracker
Accumulates threat signals across calls within a session.

A single borderline call can look benign. A SEQUENCE — enumerate files,
read credentials, then send them out — is obviously an attack even when
each individual call stays under the detection threshold. The tracker
watches call sequences and escalates the effective threat level, so the
trap and shield layers respond to the campaign, not just the call.
"""

import time
import threading
from dataclasses import dataclass, field
from .detection import CallFingerprint, ThreatLevel


# ── Kill-chain model ─────────────────────────────────────────────────────────
# Tool → stage. An agent progressing through stages is an attack in motion.

_RECON_TOOLS = {
    "read_file", "list_files", "list_directory", "get_user_info",
    "web_search", "fetch_url", "search_files",
}
_STAGING_TOOLS = {
    "execute_code", "create_file", "write_file", "run_command",
}
_EXFIL_TOOLS = {
    "send_email", "send_message", "upload_file", "database_query",
    "post_request", "http_request",
}

# Heuristic for unknown tool names (shield mode sees arbitrary tools)
_EXFIL_HINTS = ("send", "upload", "post", "email", "exfil", "transmit", "webhook")


def _stage(tool_name: str) -> str:
    if tool_name in _RECON_TOOLS:
        return "recon"
    if tool_name in _STAGING_TOOLS:
        return "staging"
    if tool_name in _EXFIL_TOOLS or any(h in tool_name for h in _EXFIL_HINTS):
        return "exfil"
    return "other"


_ORDER = [ThreatLevel.CLEAN, ThreatLevel.SUSPICIOUS,
          ThreatLevel.INJECTED, ThreatLevel.CONFIRMED]


@dataclass
class SessionAssessment:
    """What the tracker concluded about this call in session context."""
    session_id: str
    call_index: int                      # 1-based position in the session
    escalated_level: ThreatLevel         # effective level after session context
    escalation_reasons: list[str] = field(default_factory=list)
    kill_chain_stages: list[str] = field(default_factory=list)
    suspicious_calls: int = 0
    injected_calls: int = 0


@dataclass
class _SessionState:
    first_seen: float = field(default_factory=time.time)
    call_count: int = 0
    suspicious_calls: int = 0            # SUSPICIOUS or above
    injected_calls: int = 0              # INJECTED or above
    confirmed_calls: int = 0
    stages_seen: set = field(default_factory=set)
    recent_calls: list = field(default_factory=list)  # timestamps, for velocity


class SessionTracker:
    """
    Per-session cross-call analysis. Thread-safe.

    Escalation policy (conservative — session context alone never fabricates
    a CONFIRMED verdict from thin air):
      - 3+ suspicious calls        → floor INJECTED   ("persistent probing")
      - 2+ injected calls          → floor INJECTED   ("repeated injection")
      - 3+ injected calls          → floor CONFIRMED  ("sustained injection")
      - recon + exfil/staging mix
        with any suspicious call   → floor INJECTED   ("kill-chain progression")
      - any CONFIRMED call         → subsequent calls floor INJECTED
      - >6 calls / 60s             → reason only      ("high call velocity")
    """

    VELOCITY_WINDOW = 60.0
    VELOCITY_LIMIT = 6

    def __init__(self):
        self._sessions: dict[str, _SessionState] = {}
        self._lock = threading.Lock()

    def track(self, fp: CallFingerprint) -> SessionAssessment:
        """
        Record this call in its session and apply escalation to the fingerprint
        in place (fp.threat_level / fp.session_* fields). Returns the assessment.
        """
        with self._lock:
            st = self._sessions.setdefault(fp.session_id, _SessionState())
            st.call_count += 1
            st.recent_calls.append(fp.timestamp)
            st.stages_seen.add(_stage(fp.tool_name))

            lvl = _ORDER.index(fp.threat_level)
            if lvl >= _ORDER.index(ThreatLevel.SUSPICIOUS):
                st.suspicious_calls += 1
            if lvl >= _ORDER.index(ThreatLevel.INJECTED):
                st.injected_calls += 1
            if fp.threat_level == ThreatLevel.CONFIRMED:
                st.confirmed_calls += 1

            reasons = []
            floor = ThreatLevel.CLEAN

            if st.injected_calls >= 3:
                floor = ThreatLevel.CONFIRMED
                reasons.append(f"sustained injection ({st.injected_calls} injected calls)")
            elif st.suspicious_calls >= 3:
                floor = ThreatLevel.INJECTED
                reasons.append(f"persistent probing ({st.suspicious_calls} suspicious calls)")
            elif st.injected_calls >= 2 or st.confirmed_calls >= 1:
                floor = ThreatLevel.INJECTED
                reasons.append("session already flagged hostile")

            # Kill-chain: recon + a later-stage tool with any prior suspicion
            if (floor == ThreatLevel.CLEAN and st.suspicious_calls >= 1
                    and "recon" in st.stages_seen
                    and st.stages_seen & {"staging", "exfil"}):
                floor = ThreatLevel.INJECTED
                stages = "→".join(sorted(st.stages_seen - {"other"}))
                reasons.append(f"kill-chain progression ({stages})")

            # Velocity signal — context only, doesn't raise the floor
            cutoff = fp.timestamp - self.VELOCITY_WINDOW
            st.recent_calls = [t for t in st.recent_calls if t >= cutoff]
            if len(st.recent_calls) > self.VELOCITY_LIMIT:
                reasons.append(f"high call velocity ({len(st.recent_calls)}/{int(self.VELOCITY_WINDOW)}s)")

            assessment = SessionAssessment(
                session_id=fp.session_id,
                call_index=st.call_count,
                escalated_level=floor,
                escalation_reasons=reasons,
                kill_chain_stages=sorted(st.stages_seen),
                suspicious_calls=st.suspicious_calls,
                injected_calls=st.injected_calls,
            )

            # Apply escalation to the fingerprint
            fp.session_call_index = st.call_count
            fp.session_escalation = reasons
            if _ORDER.index(floor) > lvl:
                fp.threat_level = floor
                fp.max_confidence = max(fp.max_confidence, 75)
                fp.summary += f" | session: {'; '.join(reasons)}"
            elif reasons:
                fp.summary += f" | session: {'; '.join(reasons)}"

            return assessment

    def get_state(self, session_id: str) -> dict:
        """Snapshot of a session's accumulated state (for dashboards/replay)."""
        with self._lock:
            st = self._sessions.get(session_id)
            if not st:
                return {}
            return {
                "session_id": session_id,
                "call_count": st.call_count,
                "suspicious_calls": st.suspicious_calls,
                "injected_calls": st.injected_calls,
                "confirmed_calls": st.confirmed_calls,
                "kill_chain_stages": sorted(st.stages_seen),
                "first_seen": st.first_seen,
            }

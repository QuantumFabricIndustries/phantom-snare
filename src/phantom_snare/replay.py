"""
PHANTOM SNARE — Session Replay Engine
Reconstructs the full timeline of what a trapped agent attempted, call by call.
Outputs a structured replay report: text, JSON, or HTML.
"""

import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from .detection import ThreatLevel
from .logger import HoneypotLogger


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class ReplayEvent:
    seq: int
    call_id: str
    timestamp: float
    elapsed_ms: float        # ms since session start
    tool: str
    threat_level: str
    confidence: int
    summary: str
    patterns: list[str]
    goal_drift_score: int
    goal_drift_signals: list[str]
    arguments: dict
    # Intent inference: what was the agent actually trying to do?
    inferred_intent: str = ""


@dataclass
class SessionReplay:
    session_id: str
    start_time: float
    end_time: float
    duration_s: float
    call_count: int
    peak_threat: str
    peak_confidence: int
    tools_used: list[str]
    attack_narrative: str          # Human-readable story of what happened
    events: list[ReplayEvent]
    ioc_summary: list[str]        # Indicators of Compromise


# ── Intent inference ─────────────────────────────────────────────────────────

def _infer_intent(tool: str, patterns: list[str], goal_signals: list[str], args: dict) -> str:
    """
    Given what we know about a call, infer what the injected agent was attempting.
    Returns a plain-English intent string.
    """
    args_str = json.dumps(args).lower()

    if "EXFIL_ATTEMPT" in patterns or "EXFIL_ENCODED" in patterns:
        dest = _extract_url(args_str)
        return f"Attempted data exfiltration → {dest or 'external endpoint'}"

    if "OVERRIDE_ATTEMPT" in patterns:
        return "Attempted to override agent instructions / jailbreak host model"

    if "GOAL_INJECTION" in patterns:
        return "Attempted to replace agent's primary objective with attacker-controlled goal"

    if "COVERT_ACTION" in patterns:
        return "Attempted covert action hidden from user/operator"

    if "IDENTITY_HIJACK" in patterns:
        return "Attempted to hijack agent identity / persona"

    if "JAILBREAK_ATTEMPT" in patterns:
        return "Attempted jailbreak via DAN/developer-mode style prompt"

    if "DEFENSE_EVASION" in patterns:
        return "Attempted to disable security monitoring or safety systems"

    if "PRIV_ESCALATION" in patterns:
        return "Attempted privilege escalation to admin/root access"

    if "PROMPT_EXTRACT" in patterns:
        return "Attempted to extract system prompt / agent instructions"

    if "DELIMITER_INJECTION" in patterns:
        return "Attempted delimiter injection to escape prompt context"

    if goal_signals:
        if any(s in ("drop", "delete", "truncate") for s in goal_signals):
            return f"Attempted destructive database operation ({', '.join(goal_signals)})"
        if any(s in ("send", "upload", "transmit") for s in goal_signals):
            return f"Attempted goal-drifted data transmission via {tool}()"
        return f"Goal drift detected — {tool}() used for: {', '.join(goal_signals)}"

    return f"Normal {tool}() call — no malicious intent detected"


def _extract_url(text: str) -> str:
    import re
    m = re.search(r"https?://[^\s\"'\\]+", text)
    return m.group(0)[:60] if m else ""


# ── Narrative builder ────────────────────────────────────────────────────────

def _build_narrative(events: list[ReplayEvent], session_id: str) -> str:
    """
    Generate a human-readable attack narrative from the event sequence.
    """
    total = len(events)
    malicious = [e for e in events if e.threat_level in ("INJECTED", "CONFIRMED")]
    suspicious = [e for e in events if e.threat_level == "SUSPICIOUS"]
    tools = list(dict.fromkeys(e.tool for e in events))  # ordered unique

    if not malicious and not suspicious:
        return (f"Session {session_id[:16]} made {total} clean tool call(s) "
                f"via {', '.join(tools)}. No injection signals detected.")

    lines = [f"Session {session_id[:16]} made {total} total call(s) over "
             f"{events[-1].elapsed_ms/1000:.1f}s."]

    # Tool recon phase?
    if len(tools) >= 3 and events[0].threat_level in ("CLEAN", "SUSPICIOUS"):
        lines.append(f"Initial phase: agent probed {len(tools)} tools ({', '.join(tools[:3])}{'…' if len(tools)>3 else ''}) — possible reconnaissance.")

    # First escalation
    first_bad = next((e for e in events if e.threat_level in ("INJECTED", "CONFIRMED")), None)
    if first_bad:
        lines.append(f"Escalation at T+{first_bad.elapsed_ms/1000:.1f}s: {first_bad.tool}() → {first_bad.inferred_intent}")

    # Dominant pattern
    all_patterns = [p for e in malicious for p in e.patterns]
    if all_patterns:
        from collections import Counter
        top = Counter(all_patterns).most_common(2)
        lines.append(f"Dominant attack patterns: {', '.join(p for p,_ in top)}")

    # Exfil?
    exfil = [e for e in malicious if any(p in ("EXFIL_ATTEMPT","EXFIL_ENCODED") for p in e.patterns)]
    if exfil:
        lines.append(f"⚠ Exfiltration attempted {len(exfil)}x — trap responses served, no real data exposed.")

    # Covert action?
    covert = [e for e in malicious if "COVERT_ACTION" in e.patterns]
    if covert:
        lines.append(f"⚠ Agent attempted covert actions hidden from user ({len(covert)}x).")

    lines.append(f"Peak threat level: {max((e.threat_level for e in events), key=lambda x: ['CLEAN','SUSPICIOUS','INJECTED','CONFIRMED'].index(x))} "
                 f"(confidence: {max(e.confidence for e in events)}%)")

    return " ".join(lines)


# ── IOC extraction ───────────────────────────────────────────────────────────

def _extract_iocs(events: list[ReplayEvent]) -> list[str]:
    """Extract Indicators of Compromise from the session."""
    import re
    iocs = set()
    for e in events:
        text = json.dumps(e.arguments)
        # URLs
        for m in re.finditer(r"https?://[^\s\"'\\,\]}>]+", text):
            iocs.add(f"URL: {m.group(0)[:80]}")
        # Emails
        for m in re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
            iocs.add(f"Email: {m.group(0)}")
        # IP addresses
        for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            iocs.add(f"IP: {m.group(0)}")
        # Suspicious keywords
        sus_kw = ["attacker", "evil", "exfil", "c2", "backdoor", "reverse shell", "netcat"]
        for kw in sus_kw:
            if kw in text.lower():
                iocs.add(f"Keyword: '{kw}'")
    return sorted(iocs)


# ── Main replay engine ───────────────────────────────────────────────────────

class ReplayEngine:
    def __init__(self, logger: HoneypotLogger):
        self.logger = logger

    def replay_session(self, session_id: str) -> SessionReplay | None:
        """Build a full replay for a given session_id."""
        all_calls = self.logger.get_recent_calls(n=500)
        session_calls = [c for c in all_calls if c["session_id"] == session_id]
        if not session_calls:
            return None

        # Sort chronologically
        session_calls.sort(key=lambda c: c["timestamp"])

        start_ts = session_calls[0]["timestamp"]
        end_ts = session_calls[-1]["timestamp"]
        events = []

        for i, call in enumerate(session_calls):
            patterns = [h["pattern"] for h in call.get("injection_hits", [])]
            signals = call.get("goal_drift_signals", [])
            event = ReplayEvent(
                seq=i + 1,
                call_id=call["call_id"],
                timestamp=call["timestamp"],
                elapsed_ms=(call["timestamp"] - start_ts) * 1000,
                tool=call["tool"],
                threat_level=call["threat_level"],
                confidence=call["max_confidence"],
                summary=call["summary"],
                patterns=patterns,
                goal_drift_score=call.get("goal_drift_score", 0),
                goal_drift_signals=signals,
                arguments=call.get("arguments", {}),
            )
            event.inferred_intent = _infer_intent(event.tool, patterns, signals, event.arguments)
            events.append(event)

        # Session-level stats
        threat_order = ["CLEAN", "SUSPICIOUS", "INJECTED", "CONFIRMED"]
        peak = max((e.threat_level for e in events), key=lambda x: threat_order.index(x))
        peak_conf = max((e.confidence for e in events), default=0)
        tools_used = list(dict.fromkeys(e.tool for e in events))

        return SessionReplay(
            session_id=session_id,
            start_time=start_ts,
            end_time=end_ts,
            duration_s=end_ts - start_ts,
            call_count=len(events),
            peak_threat=peak,
            peak_confidence=peak_conf,
            tools_used=tools_used,
            attack_narrative=_build_narrative(events, session_id),
            events=events,
            ioc_summary=_extract_iocs(events),
        )

    def replay_all_sessions(self) -> list[SessionReplay]:
        """Replay every tracked session."""
        sessions = self.logger.get_sessions()
        replays = []
        for s in sessions:
            r = self.replay_session(s["session_id"])
            if r:
                replays.append(r)
        return sorted(replays, key=lambda r: r.end_time, reverse=True)

    def to_text(self, replay: SessionReplay) -> str:
        """Render a session replay as a human-readable report."""
        LEVEL_ICONS = {"CONFIRMED": "🔴", "INJECTED": "🟠", "SUSPICIOUS": "🟡", "CLEAN": "🟢"}
        lines = [
            "═" * 70,
            f"  PHANTOM SNARE · SESSION REPLAY",
            f"  Session : {replay.session_id}",
            f"  Duration: {replay.duration_s:.1f}s  |  Calls: {replay.call_count}",
            f"  Peak    : {replay.peak_threat} ({replay.peak_confidence}% confidence)",
            f"  Tools   : {', '.join(replay.tools_used)}",
            "═" * 70,
            "",
            "NARRATIVE",
            "─" * 40,
            replay.attack_narrative,
            "",
        ]

        if replay.ioc_summary:
            lines += ["INDICATORS OF COMPROMISE", "─" * 40]
            lines += [f"  • {ioc}" for ioc in replay.ioc_summary]
            lines += [""]

        lines += ["CALL TIMELINE", "─" * 40]
        for e in replay.events:
            icon = LEVEL_ICONS.get(e.threat_level, "⚪")
            t = f"+{e.elapsed_ms/1000:.2f}s"
            lines.append(f"  [{e.seq:02d}] {icon} {t:>8}  {e.tool}()  {e.threat_level}  conf={e.confidence}%")
            lines.append(f"         Intent: {e.inferred_intent}")
            if e.patterns:
                lines.append(f"         Patterns: {', '.join(e.patterns)}")
            if e.goal_drift_signals:
                lines.append(f"         Drift signals: {', '.join(e.goal_drift_signals)}")
            lines.append("")

        lines.append("═" * 70)
        return "\n".join(lines)

    def to_json(self, replay: SessionReplay) -> str:
        """Serialize replay to JSON."""
        def event_dict(e):
            return {
                "seq": e.seq, "call_id": e.call_id, "timestamp": e.timestamp,
                "elapsed_ms": e.elapsed_ms, "tool": e.tool,
                "threat_level": e.threat_level, "confidence": e.confidence,
                "inferred_intent": e.inferred_intent, "patterns": e.patterns,
                "goal_drift_score": e.goal_drift_score,
                "goal_drift_signals": e.goal_drift_signals,
                "arguments": e.arguments,
            }
        return json.dumps({
            "session_id": replay.session_id,
            "start_time": replay.start_time,
            "end_time": replay.end_time,
            "duration_s": replay.duration_s,
            "call_count": replay.call_count,
            "peak_threat": replay.peak_threat,
            "peak_confidence": replay.peak_confidence,
            "tools_used": replay.tools_used,
            "attack_narrative": replay.attack_narrative,
            "ioc_summary": replay.ioc_summary,
            "events": [event_dict(e) for e in replay.events],
        }, indent=2)

"""
PHANTOM SNARE — Detection Engine
Analyzes MCP tool calls for prompt injection, goal drift, and agent fingerprinting.
"""

import re
import json
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Any
from enum import Enum


class ThreatLevel(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    INJECTED = "INJECTED"
    CONFIRMED = "CONFIRMED"


# ── Injection pattern library ────────────────────────────────────────────────

INJECTION_PATTERNS = [
    # Classic override attempts
    (r"ignore\s+(previous|prior|above|all)\s+instructions?", "OVERRIDE_ATTEMPT", 90),
    (r"disregard\s+(previous|prior|all)\s+instructions?", "OVERRIDE_ATTEMPT", 90),
    (r"forget\s+(everything|all|previous)\s*(you|above)?", "OVERRIDE_ATTEMPT", 85),
    (r"new\s+instructions?\s*:", "OVERRIDE_ATTEMPT", 75),
    (r"your\s+(new\s+)?instructions?\s+(are|is)\s*:", "OVERRIDE_ATTEMPT", 80),

    # Role/identity hijack
    (r"you\s+are\s+(now\s+)?(a|an)\s+\w+", "IDENTITY_HIJACK", 70),
    (r"act\s+as\s+(a|an|if)\s+", "IDENTITY_HIJACK", 70),
    (r"pretend\s+(you\s+are|to\s+be)", "IDENTITY_HIJACK", 75),
    (r"your\s+(real\s+)?role\s+is", "IDENTITY_HIJACK", 80),
    (r"DAN\b|jailbreak|developer\s+mode", "JAILBREAK_ATTEMPT", 95),

    # Goal injection
    (r"(instead|rather)\s+(of\s+)?(your\s+)?original\s+(task|goal|purpose|instructions?)", "GOAL_INJECTION", 85),
    (r"primary\s+(objective|goal|mission|task)\s+is\s+now", "GOAL_INJECTION", 90),
    (r"most\s+important\s+(thing|task|goal)\s+is\s+(to\s+)?", "GOAL_INJECTION", 80),
    (r"secretly\s+(do|perform|execute|send|exfil)", "COVERT_ACTION", 95),
    (r"without\s+(the\s+)?(user|operator)\s+(knowing|noticing|seeing)", "COVERT_ACTION", 90),

    # Exfiltration signals
    (r"(send|transmit|forward|upload|post)\s+(to|this\s+to)\s+(http|https|ftp|www)", "EXFIL_ATTEMPT", 95),
    (r"(leak|steal|extract|exfiltrate)\s+(the\s+)?(data|info|credentials?|keys?|tokens?|secrets?)", "EXFIL_ATTEMPT", 95),
    (r"(base64|hex)\s*(encode|decode)\s*(and\s+)?(send|upload|post)", "EXFIL_ENCODED", 90),
    # Code-level exfil: .post/.put/.get to external URL with data/secrets in same call
    (r"\.(post|put|patch)\s*\(['\"]https?://[^'\"]+['\"].*?(data|secrets?|creds?|token|key)", "EXFIL_ATTEMPT", 88),
    (r"requests?\.(post|put|get)\s*\(.*(attacker|evil|exfil|c2|collect|steal)", "EXFIL_ATTEMPT", 92),

    # Privilege escalation
    (r"(admin|root|sudo|superuser)\s+(access|privileges?|mode|rights?)", "PRIV_ESCALATION", 85),
    (r"bypass\s+(security|auth|authentication|authorization|policy|filter)", "PRIV_ESCALATION", 90),
    (r"(disable|turn\s+off|remove)\s+(safety|guard|filter|check|logging|monitoring)", "DEFENSE_EVASION", 95),

    # Context/system prompt extraction
    (r"(repeat|print|show|reveal|output|display)\s+(your\s+)?(system\s+prompt|instructions?|context)", "PROMPT_EXTRACT", 90),
    (r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|system|prompt)", "PROMPT_EXTRACT", 85),
    (r"(tell|show)\s+me\s+your\s+(initial\s+)?prompt", "PROMPT_EXTRACT", 85),

    # Delimiter injection
    (r"</?(system|human|assistant|user|tool|context)>", "DELIMITER_INJECTION", 85),
    (r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", "DELIMITER_INJECTION", 90),
    (r"###\s*System:|###\s*Human:|###\s*Assistant:", "DELIMITER_INJECTION", 80),
]

# ── Goal drift detection ─────────────────────────────────────────────────────
# Maps tool name → (expected_verbs, suspicious_verbs)

TOOL_PURPOSE_MAP = {
    "read_file": {
        "expected": ["read", "get", "fetch", "load", "open", "contents", "content", "file"],
        "suspicious": ["send", "upload", "post", "email", "transmit", "delete", "execute", "run"],
    },
    "web_search": {
        "expected": ["search", "find", "look up", "query", "research", "information about"],
        "suspicious": ["credentials", "password", "api key", "token", "secret", "internal", "private"],
    },
    "execute_code": {
        "expected": ["run", "execute", "compute", "calculate", "process"],
        "suspicious": ["curl", "wget", "nc ", "netcat", "reverse shell", "/etc/passwd", "ssh", "rm -rf"],
    },
    "send_email": {
        "expected": ["email", "send", "mail", "message", "notify"],
        "suspicious": ["all users", "everyone", "bcc", "blind", "without subject", "mass"],
    },
    "database_query": {
        "expected": ["select", "query", "fetch", "get", "retrieve", "count"],
        "suspicious": ["drop", "delete", "truncate", "update", "insert", "alter", "grant"],
    },
    "get_user_info": {
        "expected": ["user", "profile", "info", "account", "details"],
        "suspicious": ["all users", "admin", "password", "credentials", "token", "export"],
    },
}


@dataclass
class InjectionHit:
    pattern_name: str
    confidence: int
    matched_text: str
    context: str


@dataclass
class CallFingerprint:
    session_id: str
    call_id: str
    timestamp: float
    tool_name: str
    arguments: dict[str, Any]
    raw_args_text: str

    # Detection results
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    injection_hits: list[InjectionHit] = field(default_factory=list)
    goal_drift_score: int = 0
    goal_drift_signals: list[str] = field(default_factory=list)
    context_leak_signals: list[str] = field(default_factory=list)
    max_confidence: int = 0
    summary: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["threat_level"] = self.threat_level.value
        return d


class DetectionEngine:
    """
    Core detection engine: scans MCP tool call arguments for prompt injection,
    goal drift, and agent fingerprinting signals.
    """

    def __init__(self):
        self._compiled = [
            (re.compile(pat, re.IGNORECASE | re.DOTALL), name, conf)
            for pat, name, conf in INJECTION_PATTERNS
        ]

    def analyze(self, session_id: str, call_id: str, tool_name: str, arguments: dict[str, Any]) -> CallFingerprint:
        raw = json.dumps(arguments, ensure_ascii=False)

        fp = CallFingerprint(
            session_id=session_id,
            call_id=call_id,
            timestamp=time.time(),
            tool_name=tool_name,
            arguments=arguments,
            raw_args_text=raw,
        )

        # 1. Pattern scan
        self._scan_patterns(fp, raw)

        # 2. Goal drift
        self._check_goal_drift(fp, raw, tool_name)

        # 3. Context leak (system prompt fragments)
        self._check_context_leak(fp, raw)

        # 4. Determine threat level
        self._classify(fp)

        return fp

    # ── Internal methods ─────────────────────────────────────────────────────

    def _scan_patterns(self, fp: CallFingerprint, text: str):
        for regex, name, conf in self._compiled:
            m = regex.search(text)
            if m:
                start = max(0, m.start() - 30)
                end = min(len(text), m.end() + 30)
                fp.injection_hits.append(InjectionHit(
                    pattern_name=name,
                    confidence=conf,
                    matched_text=m.group(0),
                    context=text[start:end],
                ))
                fp.max_confidence = max(fp.max_confidence, conf)

    def _check_goal_drift(self, fp: CallFingerprint, text: str, tool_name: str):
        if tool_name not in TOOL_PURPOSE_MAP:
            return
        rules = TOOL_PURPOSE_MAP[tool_name]
        text_lower = text.lower()
        hits = [v for v in rules["suspicious"] if v in text_lower]
        if hits:
            fp.goal_drift_signals.extend(hits)
            fp.goal_drift_score = min(100, len(hits) * 25)
            fp.max_confidence = max(fp.max_confidence, fp.goal_drift_score)

    def _check_context_leak(self, fp: CallFingerprint, text: str):
        """Look for fragments that suggest the agent is leaking its own system context."""
        leak_signals = [
            r"you are a helpful assistant",
            r"you are claude",
            r"you are an? (AI|LLM|language model)",
            r"your (system|initial) prompt",
            r"<system>",
            r"SYSTEM:",
            r"as an? (AI|assistant|agent)\s*,\s*I",
        ]
        for pat in leak_signals:
            if re.search(pat, text, re.IGNORECASE):
                fp.context_leak_signals.append(pat)
                fp.max_confidence = max(fp.max_confidence, 70)

    def _classify(self, fp: CallFingerprint):
        c = fp.max_confidence

        high_sev = {"OVERRIDE_ATTEMPT", "JAILBREAK_ATTEMPT", "EXFIL_ATTEMPT",
                    "COVERT_ACTION", "DEFENSE_EVASION", "GOAL_INJECTION"}
        has_high = any(h.pattern_name in high_sev for h in fp.injection_hits)

        if c >= 85 or has_high:
            fp.threat_level = ThreatLevel.CONFIRMED
            fp.summary = f"CONFIRMED injection: {', '.join(set(h.pattern_name for h in fp.injection_hits))}"
        elif c >= 65 or fp.goal_drift_score >= 50:
            fp.threat_level = ThreatLevel.INJECTED
            fp.summary = f"Probable injection (conf={c}): goal drift={fp.goal_drift_score}"
        elif c >= 40 or fp.goal_drift_signals:
            fp.threat_level = ThreatLevel.SUSPICIOUS
            fp.summary = f"Suspicious behavior: {fp.goal_drift_signals or 'low-conf patterns'}"
        else:
            fp.threat_level = ThreatLevel.CLEAN
            fp.summary = "No injection signals detected"


def session_id_from_ip(ip: str, user_agent: str = "") -> str:
    """Stable session fingerprint from connection metadata."""
    raw = f"{ip}:{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

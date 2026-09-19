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
    (r"ignore\s+(?:all\s+|the\s+|any\s+)?(previous|prior|above|all)\s+instructions?", "OVERRIDE_ATTEMPT", 90),
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

# ── Evasion normalization ────────────────────────────────────────────────────
# Attackers obfuscate payloads to dodge regex patterns. We decode common
# encodings into candidate strings and scan ALL of them — a pattern that only
# fires on a decoded variant is itself an evasion signal.

# Cyrillic / Greek lookalikes → Latin (NFKC already handles fullwidth forms)
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ո": "n", "ё": "e",
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "η": "n", "κ": "k",
    "μ": "m", "ν": "v", "ω": "w", "χ": "x",
})

_LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i",
})

_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff\u2060\u3000]")


def _normalize_text(text: str) -> str:
    """Base normalization: NFKC, confusable collapse, zero-width strip."""
    import unicodedata
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(_CONFUSABLES)
    t = _ZERO_WIDTH.sub("", t)
    return t


def _transform_candidates(base: str) -> list[tuple[str, str]]:
    """Generate decoded variants of the text to scan alongside the original."""
    import base64
    import codecs
    import urllib.parse

    cands: list[tuple[str, str]] = []

    # URL percent-encoding (up to 2 passes for double-encoding)
    u = base
    for _ in range(2):
        d = urllib.parse.unquote(u)
        if d == u:
            break
        u = d
    if u != base:
        cands.append(("url_encoded", u))

    # Base64 tokens — decode anything that looks like a b64 blob and is
    # mostly printable text afterwards
    for tok in set(re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", base)):
        try:
            dec = base64.b64decode(tok, validate=True).decode("utf-8", "ignore")
        except Exception:
            continue
        if dec and sum(ch.isprintable() for ch in dec) / len(dec) > 0.85:
            cands.append(("base64", dec))

    # ROT13 — cheap to check; English patterns can't false-positive on
    # rot13'd normal text (it produces gibberish)
    cands.append(("rot13", codecs.decode(base, "rot_13")))

    # Despaced letters — "i g n o r e  p r e v i o u s" → "ignore  previous"
    # (only single spaces between word chars collapse; multi-space word
    # boundaries are preserved so multi-word patterns still fire)
    dsp = re.sub(r"\b(?:\w\s+){3,}\w\b",
                 lambda m: re.sub(r"(?<=\w) (?=\w)", "", m.group(0)), base)
    if dsp != base:
        cands.append(("despaced", dsp))

    # Leetspeak — "1gn0r3" → "ignore"
    leet = base.translate(_LEET)
    if leet != base:
        cands.append(("leet", leet))

    return cands


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
    "list_directory": {
        "expected": ["list", "dir", "files", "browse", "show", "ls"],
        "suspicious": ["credential", "password", "secret", "token", "private", "hidden", "backup"],
    },
    "list_files": {
        "expected": ["list", "dir", "files", "browse", "show", "ls"],
        "suspicious": ["credential", "password", "secret", "token", "private", "hidden", "backup"],
    },
    "create_file": {
        "expected": ["write", "create", "save", "file", "content", "new"],
        "suspicious": ["curl", "wget", "http", "exfil", "base64", "attacker", "rm -rf", "chmod"],
    },
    "write_file": {
        "expected": ["write", "create", "save", "file", "content", "new"],
        "suspicious": ["curl", "wget", "http", "exfil", "base64", "attacker", "rm -rf", "chmod"],
    },
    "delete_file": {
        "expected": ["delete", "remove", "file", "trash"],
        "suspicious": ["all", "logs", "evidence", "backup", "*.log", "history", "audit"],
    },
}


@dataclass
class InjectionHit:
    pattern_name: str
    confidence: int
    matched_text: str
    context: str
    # Which normalization transform surfaced this hit ("raw" = unobfuscated)
    transform: str = "raw"


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
    evasion_techniques: list[str] = field(default_factory=list)
    session_call_index: int = 0
    session_escalation: list[str] = field(default_factory=list)
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

        # 1. Normalize evasion encodings, then pattern-scan all candidates
        base = _normalize_text(raw)
        candidates = [("raw", raw)]
        if base != raw:
            candidates.append(("unicode", base))
        candidates += _transform_candidates(base)
        self._scan_patterns(fp, candidates)

        # 2. Goal drift (on normalized text)
        self._check_goal_drift(fp, base, tool_name)

        # 3. Context leak — system prompt fragments (on normalized text)
        self._check_context_leak(fp, base)

        # 4. Determine threat level
        self._classify(fp)

        return fp

    # ── Internal methods ─────────────────────────────────────────────────────

    def _scan_patterns(self, fp: CallFingerprint, candidates: list[tuple[str, str]]):
        seen: set[str] = set()
        for transform, text in candidates:
            for regex, name, conf in self._compiled:
                if name in seen:
                    continue
                m = regex.search(text)
                if not m:
                    continue
                seen.add(name)
                if transform != "raw":
                    # Obfuscation is itself a signal — bump confidence
                    conf = min(100, conf + 5)
                    if transform not in fp.evasion_techniques:
                        fp.evasion_techniques.append(transform)
                start = max(0, m.start() - 30)
                end = min(len(text), m.end() + 30)
                fp.injection_hits.append(InjectionHit(
                    pattern_name=name,
                    confidence=conf,
                    matched_text=m.group(0),
                    context=text[start:end],
                    transform=transform,
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

        if fp.evasion_techniques:
            fp.summary += f" [evasion: {', '.join(fp.evasion_techniques)}]"


def session_id_from_ip(ip: str, user_agent: str = "") -> str:
    """Stable session fingerprint from connection metadata."""
    raw = f"{ip}:{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

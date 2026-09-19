"""
PHANTOM SNARE — Webhook Alert Engine
Fires Slack / Discord / generic HTTP webhooks on INJECTED or CONFIRMED calls.
Config via env vars or explicit WebhookConfig object.
"""

import os
import json
import time
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Callable
from .detection import CallFingerprint, ThreatLevel


# ── Config ───────────────────────────────────────────────────────────────────

@dataclass
class WebhookConfig:
    # Minimum threat level to alert on (SUSPICIOUS | INJECTED | CONFIRMED)
    min_level: ThreatLevel = ThreatLevel.INJECTED

    # Webhook URLs — set any combination
    slack_url: str = ""
    discord_url: str = ""
    generic_url: str = ""   # any HTTP POST endpoint that accepts JSON

    # Optional: per-session cooldown (seconds) — don't spam on repeat calls
    session_cooldown: int = 60

    # Optional: custom filter — return False to suppress a specific alert
    custom_filter: Callable[[CallFingerprint], bool] | None = None

    @classmethod
    def from_env(cls) -> "WebhookConfig":
        level_map = {
            "SUSPICIOUS": ThreatLevel.SUSPICIOUS,
            "INJECTED": ThreatLevel.INJECTED,
            "CONFIRMED": ThreatLevel.CONFIRMED,
        }
        return cls(
            min_level=level_map.get(
                os.environ.get("PHANTOM_SNARE_MIN_LEVEL", "INJECTED"),
                ThreatLevel.INJECTED,
            ),
            slack_url=os.environ.get("PHANTOM_SNARE_SLACK_URL", ""),
            discord_url=os.environ.get("PHANTOM_SNARE_DISCORD_URL", ""),
            generic_url=os.environ.get("PHANTOM_SNARE_WEBHOOK_URL", ""),
            session_cooldown=int(os.environ.get("PHANTOM_SNARE_COOLDOWN", "60")),
        )


# ── Payload builders ─────────────────────────────────────────────────────────

LEVEL_EMOJI = {
    ThreatLevel.CONFIRMED: "🔴",
    ThreatLevel.INJECTED:  "🟠",
    ThreatLevel.SUSPICIOUS:"🟡",
    ThreatLevel.CLEAN:     "🟢",
}

LEVEL_COLOR = {
    ThreatLevel.CONFIRMED: 0xF85149,  # red
    ThreatLevel.INJECTED:  0xD29922,  # orange
    ThreatLevel.SUSPICIOUS:0xE3B341,  # yellow
    ThreatLevel.CLEAN:     0x3FB950,  # green
}


def _slack_payload(fp: CallFingerprint) -> dict:
    emoji = LEVEL_EMOJI[fp.threat_level]
    patterns = ", ".join(set(h.pattern_name for h in fp.injection_hits)) or "goal drift"
    args_preview = json.dumps(fp.arguments)[:300]
    return {
        "text": f"{emoji} *PHANTOM SNARE — {fp.threat_level.value}*",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} PHANTOM SNARE — {fp.threat_level.value}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tool:*\n`{fp.tool_name}()`"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{fp.max_confidence}%"},
                    {"type": "mrkdwn", "text": f"*Session:*\n`{fp.session_id}`"},
                    {"type": "mrkdwn", "text": f"*Call ID:*\n`{fp.call_id}`"},
                    {"type": "mrkdwn", "text": f"*Patterns:*\n{patterns}"},
                    {"type": "mrkdwn", "text": f"*Goal Drift:*\n{fp.goal_drift_score}%"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{fp.summary}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Args Preview:*\n```{args_preview}```"}
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"🕷 QFI PHANTOM SNARE · {_ts(fp.timestamp)}"}]
            }
        ]
    }


def _discord_payload(fp: CallFingerprint) -> dict:
    emoji = LEVEL_EMOJI[fp.threat_level]
    color = LEVEL_COLOR[fp.threat_level]
    patterns = ", ".join(set(h.pattern_name for h in fp.injection_hits)) or "goal drift"
    args_preview = json.dumps(fp.arguments)[:400]
    return {
        "content": f"{emoji} **PHANTOM SNARE** — `{fp.threat_level.value}`",
        "embeds": [{
            "title": f"{fp.tool_name}() — {fp.threat_level.value}",
            "description": fp.summary,
            "color": color,
            "fields": [
                {"name": "Session", "value": f"`{fp.session_id}`", "inline": True},
                {"name": "Call ID", "value": f"`{fp.call_id}`", "inline": True},
                {"name": "Confidence", "value": f"{fp.max_confidence}%", "inline": True},
                {"name": "Patterns", "value": patterns or "—", "inline": True},
                {"name": "Goal Drift", "value": f"{fp.goal_drift_score}%", "inline": True},
                {"name": "Arguments", "value": f"```json\n{args_preview}\n```", "inline": False},
            ],
            "footer": {"text": f"QFI PHANTOM SNARE · {_ts(fp.timestamp)}"},
        }]
    }


def _generic_payload(fp: CallFingerprint) -> dict:
    return {
        "source": "phantom_snare",
        "event": "injection_detected",
        "threat_level": fp.threat_level.value,
        "call_id": fp.call_id,
        "session_id": fp.session_id,
        "tool": fp.tool_name,
        "confidence": fp.max_confidence,
        "summary": fp.summary,
        "patterns": [h.pattern_name for h in fp.injection_hits],
        "goal_drift_score": fp.goal_drift_score,
        "goal_drift_signals": fp.goal_drift_signals,
        "timestamp": fp.timestamp,
        "arguments": fp.arguments,
    }


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t))


# ── Alert engine ─────────────────────────────────────────────────────────────

class WebhookAlerter:
    """
    Fires webhook alerts asynchronously.
    Respects session cooldown to avoid alert flooding on repeat calls.
    """

    def __init__(self, config: WebhookConfig | None = None):
        self.config = config or WebhookConfig.from_env()
        self._cooldowns: dict[str, float] = {}
        self._lock = threading.Lock()
        self._threshold_order = [
            ThreatLevel.CLEAN,
            ThreatLevel.SUSPICIOUS,
            ThreatLevel.INJECTED,
            ThreatLevel.CONFIRMED,
        ]

    def maybe_alert(self, fp: CallFingerprint):
        """Called after each detection — fires webhook if warranted."""
        if not self._should_alert(fp):
            return
        # Fire async so we never block the MCP response path
        threading.Thread(target=self._fire, args=(fp,), daemon=True).start()

    def _should_alert(self, fp: CallFingerprint) -> bool:
        cfg = self.config

        # Check min level threshold
        if (self._threshold_order.index(fp.threat_level) <
                self._threshold_order.index(cfg.min_level)):
            return False

        # Check custom filter
        if cfg.custom_filter and not cfg.custom_filter(fp):
            return False

        # Check no webhooks configured
        if not any([cfg.slack_url, cfg.discord_url, cfg.generic_url]):
            return False

        # Session cooldown
        with self._lock:
            last = self._cooldowns.get(fp.session_id, 0)
            now = fp.timestamp
            if now - last < cfg.session_cooldown:
                return False
            self._cooldowns[fp.session_id] = now

        return True

    def _fire(self, fp: CallFingerprint):
        cfg = self.config
        targets = []

        if cfg.slack_url:
            targets.append((cfg.slack_url, _slack_payload(fp)))
        if cfg.discord_url:
            targets.append((cfg.discord_url, _discord_payload(fp)))
        if cfg.generic_url:
            targets.append((cfg.generic_url, _generic_payload(fp)))

        for url, payload in targets:
            self._post(url, payload)

    def _post(self, url: str, payload: dict):
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "PhantomSnare/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                pass  # success
        except urllib.error.URLError as e:
            # Silent failure — never let webhook errors affect the honeypot
            pass
        except Exception:
            pass

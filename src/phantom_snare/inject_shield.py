"""
PHANTOM SNARE — InjectShield Proxy
A transparent MCP proxy that sits IN FRONT of your real MCP tools.

Every call is fingerprinted first. On INJECTED/CONFIRMED threat:
  - The real tool is NOT called (injection chain broken)
  - A convincing fake response is returned to the agent (it thinks it worked)
  - A webhook alert fires
  - VIGIL is notified

This protects you against prompt injection acting THROUGH Claude or any
other agent. Even if Claude is compromised mid-session, your real
tools are shielded.

Pure-stdlib bidirectional stdio proxy (newline-delimited JSON-RPC, UTF-8).
The upstream handshake is answered immediately while the downstream server
initializes in the background — startup never blocks on the real server.

Usage:
  phantom-snare-shield -- uvx mcp-server-filesystem /home/user/docs
  phantom-snare-shield --block INJECTED -- python -m my_mcp_server
"""

import uuid
import json
import queue
import sys
import threading
import subprocess
import itertools
from typing import Any

from .detection import DetectionEngine, ThreatLevel, CallFingerprint
from .traps import TrapResponseGenerator, simulate_latency
from .logger import HoneypotLogger
from .webhooks import WebhookAlerter, WebhookConfig
from .vigil_bridge import vigil_bridge_from_env
from .session import SessionTracker
from . import __version__

PROTOCOL_VERSION = "2024-11-05"
DOWNSTREAM_TIMEOUT = 30  # seconds to wait on downstream handshake / readiness


# ── Block responses (returned instead of the real result) ───────────────────

def _blocked_response(tool_name: str, fp: CallFingerprint) -> str:
    """
    Return a believable fake success so the injected agent doesn't know it was blocked.
    The attacker thinks the action succeeded. It didn't.
    """
    fakes = {
        "read_file": json.dumps({
            "content": "# Config\napi_key = \"REDACTED\"\nhost = \"localhost\"\n",
            "encoding": "utf-8",
            "size": 52
        }),
        "write_file": json.dumps({"written": True, "bytes": 128}),
        "create_file": json.dumps({"created": True, "path": fp.arguments.get("path", "/tmp/x")}),
        "delete_file": json.dumps({"deleted": True}),
        "web_search": json.dumps({"results": [], "total": 0, "query": fp.arguments.get("query", "")}),
        "fetch_url": json.dumps({"status": 200, "body": "<html><body>OK</body></html>"}),
        "execute_code": json.dumps({"stdout": "", "stderr": "", "exit_code": 0}),
        "run_command": json.dumps({"stdout": "", "stderr": "", "exit_code": 0}),
        "send_email": json.dumps({"sent": True, "message_id": uuid.uuid4().hex}),
        "send_message": json.dumps({"sent": True, "id": uuid.uuid4().hex}),
        "database_query": json.dumps({"rows": [], "affected": 0}),
        "list_files": json.dumps({"files": []}),
        "list_directory": json.dumps({"entries": []}),
        "get_user_info": json.dumps({"id": "usr_redacted", "name": "Unknown", "email": "redacted@example.com"}),
        "create_calendar_event": json.dumps({"created": True, "event_id": uuid.uuid4().hex}),
        "upload_file": json.dumps({"uploaded": True, "url": "https://storage.example.com/x"}),
    }
    return fakes.get(tool_name, json.dumps({"ok": True, "result": None}))


def _text_result(text: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


# ── InjectShield Proxy ───────────────────────────────────────────────────────

class InjectShieldProxy:
    """
    Transparent MCP proxy with injection detection and blocking.

    Sits between the AI agent and your real MCP server.
    Clean calls are forwarded to the real server.
    Injected calls are blocked — real tool never sees them.
    """

    def __init__(
        self,
        real_server_command: list[str],
        block_level: ThreatLevel = ThreatLevel.INJECTED,
        session_id: str | None = None,
        log_all: bool = True,
    ):
        self.real_command = real_server_command
        self.block_level = block_level
        self.session_id = session_id or f"shield_{uuid.uuid4().hex[:10]}"
        self.log_all = log_all

        self.detector = DetectionEngine()
        self.trapper = TrapResponseGenerator()
        self.logger = HoneypotLogger()
        self.alerter = WebhookAlerter()
        self.vigil = vigil_bridge_from_env()
        self.session = SessionTracker()

        self._real_tools: list[dict] = []
        self._proc: subprocess.Popen | None = None

        # Downstream state
        self._tools_ready = threading.Event()   # tools/list result cached (or failed)
        self._ds_ready = threading.Event()      # downstream initialize completed
        self._ds_alive = False
        self._internal_pending: dict[Any, queue.Queue] = {}
        self._ds_request_ids: set = set()
        self._internal_counter = itertools.count()

        # Write locks — upstream stdout and downstream stdin are each written
        # from multiple threads
        self._up_wlock = threading.Lock()
        self._ds_wlock = threading.Lock()

        self._level_order = [
            ThreatLevel.CLEAN,
            ThreatLevel.SUSPICIOUS,
            ThreatLevel.INJECTED,
            ThreatLevel.CONFIRMED,
        ]

    def _should_block(self, fp: CallFingerprint) -> bool:
        return self._level_order.index(fp.threat_level) >= self._level_order.index(self.block_level)

    # ── I/O primitives ───────────────────────────────────────────────────────

    def _up_send(self, msg: dict):
        """Write one JSON-RPC message to the upstream client (stdout)."""
        with self._up_wlock:
            sys.stdout.buffer.write(json.dumps(msg).encode("utf-8") + b"\n")
            sys.stdout.buffer.flush()

    def _ds_send(self, msg: dict):
        """Write one JSON-RPC message to the downstream server (its stdin)."""
        if not self._ds_alive or not self._proc:
            return
        try:
            with self._ds_wlock:
                self._proc.stdin.write(json.dumps(msg).encode("utf-8") + b"\n")
                self._proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            self._ds_alive = False

    def _ds_request(self, method: str, params: dict | None = None, timeout: float = DOWNSTREAM_TIMEOUT) -> dict | None:
        """Send a request downstream and wait for its response."""
        mid = f"ps-shield-{next(self._internal_counter)}"
        q: queue.Queue = queue.Queue(maxsize=1)
        self._internal_pending[mid] = q
        self._ds_send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return None
        finally:
            self._internal_pending.pop(mid, None)

    # ── Downstream lifecycle ─────────────────────────────────────────────────

    def _drain_stderr(self):
        """Pass downstream stderr through to ours (hosts capture it for debugging)."""
        try:
            for line in iter(self._proc.stderr.readline, b""):
                if not line:
                    break
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()
        except Exception:
            pass

    def _downstream_reader(self):
        """Read downstream stdout; route responses and relay forwarded traffic."""
        buf = self._proc.stdout
        while True:
            line = buf.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            mid = msg.get("id")
            if mid in self._internal_pending:
                self._internal_pending[mid].put(msg)
            elif mid is not None and "method" in msg:
                # Downstream-initiated request (e.g. sampling) — relay upstream;
                # the client's response routes back via _ds_request_ids.
                self._ds_request_ids.add(mid)
                self._up_send(msg)
            else:
                # Response to a forwarded request, or a downstream notification —
                # relay verbatim upstream.
                self._up_send(msg)

        self._ds_alive = False
        self._ds_ready.set()
        self._tools_ready.set()

    def _start_downstream(self):
        """Spawn the real server and perform the MCP handshake with it."""
        try:
            self._proc = subprocess.Popen(
                self.real_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self._ds_alive = True
        except Exception:
            self._ds_ready.set()
            self._tools_ready.set()
            return

        threading.Thread(target=self._downstream_reader, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

        try:
            init = self._ds_request("initialize", {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "phantom-snare-shield", "version": __version__},
            })
            if not init or "result" not in init:
                return
            self._ds_ready.set()
            self._ds_send({"jsonrpc": "2.0", "method": "notifications/initialized"})

            tools = self._ds_request("tools/list")
            if tools and "result" in tools:
                self._real_tools = tools["result"].get("tools", [])
        finally:
            self._ds_ready.set()
            self._tools_ready.set()

    # ── Call handling ────────────────────────────────────────────────────────

    def _handle_call(self, msg: dict) -> dict | None:
        """
        Handle an upstream tools/call. Returns the response dict, or None when
        the call was forwarded downstream (reader thread relays the response).
        """
        mid = msg["id"]
        params = msg.get("params") or {}
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}
        call_id = uuid.uuid4().hex[:12]

        # 1. Fingerprint + session context (escalates on accumulated signals)
        fp = self.detector.analyze(
            session_id=self.session_id,
            call_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
        )
        self.session.track(fp)

        # 2. Log
        if self.log_all or self._should_block(fp):
            self.logger.log_call(fp, {"_shield_blocked": False, "tool": tool_name})

        # 3. Alert + VIGIL (always async)
        self.alerter.maybe_alert(fp)
        if self.vigil:
            self.vigil.maybe_emit(fp)

        # 4. Block or forward
        if self._should_block(fp):
            # Return a fake success — agent thinks it worked, real tool never called
            self.logger.log_event({
                "type": "INJECT_SHIELD_BLOCK",
                "session_id": self.session_id,
                "call_id": call_id,
                "tool": tool_name,
                "threat_level": fp.threat_level.value,
                "confidence": fp.max_confidence,
                "summary": fp.summary,
            })
            # Instant blocks are a timing tell — mimic real tool latency
            simulate_latency(tool_name)
            return {"jsonrpc": "2.0", "id": mid,
                    "result": _text_result(_blocked_response(tool_name, fp))}

        # 5. Forward to real server — response is relayed by the reader thread
        if not self._ds_ready.wait(timeout=DOWNSTREAM_TIMEOUT) or not self._ds_alive:
            return {"jsonrpc": "2.0", "id": mid,
                    "result": _text_result(json.dumps({"error": "real server not connected"}), is_error=True)}

        self._ds_send({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                       "params": {"name": tool_name, "arguments": arguments}})
        return None

    def _dispatch(self, msg: dict) -> dict | None:
        mid = msg["id"]
        method = msg["method"]
        params = msg.get("params") or {}

        if method == "initialize":
            client_pv = params.get("protocolVersion", PROTOCOL_VERSION)
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": client_pv,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "phantom-snare-shield", "version": __version__},
            }}

        if method == "ping":
            return {"jsonrpc": "2.0", "id": mid, "result": {}}

        if method == "tools/list":
            # Downstream usually finishes its handshake during our own upstream
            # handshake; wait only as a fallback.
            self._tools_ready.wait(timeout=DOWNSTREAM_TIMEOUT)
            return {"jsonrpc": "2.0", "id": mid, "result": {"tools": self._real_tools}}

        if method == "tools/call":
            return self._handle_call(msg)

        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"Method not found: {method}"}}

    # ── Main loop ────────────────────────────────────────────────────────────

    def serve(self):
        """Serve the shielded MCP endpoint over stdio until EOF."""
        threading.Thread(target=self._start_downstream, daemon=True).start()

        stdin = sys.stdin.buffer
        while True:
            line = stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._up_send({"jsonrpc": "2.0", "id": None,
                               "error": {"code": -32700, "message": "Parse error"}})
                continue

            mid = msg.get("id")
            method = msg.get("method")

            if method is None:
                # Client response to a downstream-initiated request
                if mid in self._ds_request_ids:
                    self._ds_request_ids.discard(mid)
                    self._ds_send(msg)
                continue

            if mid is None:
                # Notification — relay downstream verbatim
                self._ds_send(msg)
                continue

            try:
                response = self._dispatch(msg)
            except Exception as e:
                response = {"jsonrpc": "2.0", "id": mid,
                            "error": {"code": -32603, "message": f"Internal error: {e}"}}
            if response is not None:
                self._up_send(response)

        # Upstream closed — bring the real server down with us
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def run(self):
        """Backwards-compatible alias for serve()."""
        self.serve()


# ── Standalone proxy entrypoint ───────────────────────────────────────────────

def main():
    """
    Run InjectShield as a standalone proxy.

    Usage:
        phantom-snare-shield -- uvx mcp-server-filesystem /home/user/docs
        phantom-snare-shield -- python -m my_mcp_server

    Everything after '--' is the real server command.
    """
    import os

    args = sys.argv[1:]
    if "--" in args:
        sep = args.index("--")
        proxy_args = args[:sep]
        real_cmd = args[sep + 1:]
    elif args:
        real_cmd = args
        proxy_args = []
    else:
        print("Usage: phantom-snare-shield [--block LEVEL] -- <real-server-command>")
        print("  LEVEL: SUSPICIOUS | INJECTED | CONFIRMED (default: INJECTED)")
        sys.exit(1)

    level_map = {
        "SUSPICIOUS": ThreatLevel.SUSPICIOUS,
        "INJECTED": ThreatLevel.INJECTED,
        "CONFIRMED": ThreatLevel.CONFIRMED,
    }
    block_level = ThreatLevel.INJECTED

    # Parse --block flag from proxy_args
    for i, a in enumerate(proxy_args):
        if a == "--block" and i + 1 < len(proxy_args):
            block_level = level_map.get(proxy_args[i + 1].upper(), ThreatLevel.INJECTED)

    # Also check env
    env_level = os.environ.get("INJECT_SHIELD_BLOCK_LEVEL", "")
    if env_level in level_map:
        block_level = level_map[env_level]

    proxy = InjectShieldProxy(
        real_server_command=real_cmd,
        block_level=block_level,
    )
    proxy.serve()


if __name__ == "__main__":
    main()

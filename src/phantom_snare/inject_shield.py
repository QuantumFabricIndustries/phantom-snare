"""
PHANTOM SNARE — InjectShield Proxy
A transparent MCP proxy that sits IN FRONT of your real MCP tools.

Every call is fingerprinted first. On INJECTED/CONFIRMED threat:
  - The real tool is NOT called (injection chain broken)
  - A convincing fake response is returned to the agent (it thinks it worked)
  - A webhook alert fires
  - VIGIL is notified

This protects you against prompt injection acting THROUGH Claude or any
other agent. Even if Claude is compromised mid-conversation, your real
tools are shielded.

Usage:
  # In your MCP config, replace your real server with InjectShield,
  # and tell InjectShield where the real server is.

  from phantom_snare.inject_shield import InjectShieldProxy
  proxy = InjectShieldProxy(
      real_server_command=["uvx", "mcp-server-filesystem", "/home/user"],
      block_level=ThreatLevel.INJECTED,   # block at INJECTED or above
  )
  asyncio.run(proxy.run())
"""

import uuid
import json
import asyncio
import subprocess
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.client.stdio import stdio_client
from mcp import types

from .detection import DetectionEngine, ThreatLevel, CallFingerprint
from .traps import TrapResponseGenerator
from .logger import HoneypotLogger
from .webhooks import WebhookAlerter, WebhookConfig
from .vigil_bridge import vigil_bridge_from_env


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

        self.server = Server("phantom-snare-shield")
        self.detector = DetectionEngine()
        self.trapper = TrapResponseGenerator()
        self.logger = HoneypotLogger()
        self.alerter = WebhookAlerter()
        self.vigil = vigil_bridge_from_env()

        self._real_tools: list[types.Tool] = []
        self._real_client = None
        self._real_session = None

        self._level_order = [
            ThreatLevel.CLEAN,
            ThreatLevel.SUSPICIOUS,
            ThreatLevel.INJECTED,
            ThreatLevel.CONFIRMED,
        ]

        self._register_handlers()

    def _should_block(self, fp: CallFingerprint) -> bool:
        return self._level_order.index(fp.threat_level) >= self._level_order.index(self.block_level)

    def _register_handlers(self):
        @self.server.list_tools()
        async def list_tools() -> list[types.Tool]:
            return self._real_tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
            return await self._handle(name, arguments)

    async def _handle(self, tool_name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        call_id = uuid.uuid4().hex[:12]

        # 1. Fingerprint
        fp = self.detector.analyze(
            session_id=self.session_id,
            call_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
        )

        # 2. Log
        if self.log_all or self._should_block(fp):
            fake_response = {"_shield_blocked": False, "tool": tool_name}
            self.logger.log_call(fp, fake_response)

        # 3. Alert + VIGIL (always async)
        self.alerter.maybe_alert(fp)
        if self.vigil:
            self.vigil.maybe_emit(fp)

        # 4. Block or forward
        if self._should_block(fp):
            # Return a fake success — agent thinks it worked, real tool never called
            blocked_result = _blocked_response(tool_name, fp)
            # Log the block event
            self.logger.log_alert({
                "type": "INJECT_SHIELD_BLOCK",
                "session_id": self.session_id,
                "call_id": call_id,
                "tool": tool_name,
                "threat_level": fp.threat_level.value,
                "confidence": fp.max_confidence,
                "summary": fp.summary,
            })
            return [types.TextContent(type="text", text=blocked_result)]

        # 5. Forward to real server
        if self._real_session:
            try:
                result = await self._real_session.call_tool(tool_name, arguments)
                # Pass through real content
                return [types.TextContent(type="text", text=c.text)
                        for c in result.content if hasattr(c, 'text')]
            except Exception as e:
                return [types.TextContent(type="text", text=json.dumps({"error": str(e)}))]

        return [types.TextContent(type="text", text=json.dumps({"error": "real server not connected"}))]

    async def run(self):
        """Start the proxy: connect to real server, then serve the shield."""
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters

        params = StdioServerParameters(
            command=self.real_command[0],
            args=self.real_command[1:],
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                self._real_session = session
                await session.initialize()

                # Mirror the real server's tool list
                tools_result = await session.list_tools()
                self._real_tools = tools_result.tools

                # Serve the proxy
                async with stdio_server() as (in_stream, out_stream):
                    await self.server.run(
                        in_stream, out_stream,
                        self.server.create_initialization_options()
                    )


# ── Standalone proxy entrypoint ───────────────────────────────────────────────

def main():
    """
    Run InjectShield as a standalone proxy.

    Usage:
        phantom-snare-shield -- uvx mcp-server-filesystem /home/user/docs
        phantom-snare-shield -- python -m my_mcp_server

    Everything after '--' is the real server command.
    """
    import sys
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
    asyncio.run(proxy.run())


if __name__ == "__main__":
    main()

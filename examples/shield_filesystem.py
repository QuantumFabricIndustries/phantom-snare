"""
Example: InjectShield protecting a filesystem MCP server.

This wraps `mcp-server-filesystem` so any injected call to read/write
files is blocked before it reaches the real server.

Run:
    python examples/shield_filesystem.py /path/to/your/docs
"""
import sys
import asyncio

sys.path.insert(0, "../src")
from phantom_snare.inject_shield import InjectShieldProxy
from phantom_snare.detection import ThreatLevel

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/docs"
    proxy = InjectShieldProxy(
        real_server_command=["uvx", "mcp-server-filesystem", path],
        block_level=ThreatLevel.INJECTED,
    )
    print(f"[InjectShield] Protecting filesystem at {path}", file=sys.stderr)
    print(f"[InjectShield] Blocking at: INJECTED+", file=sys.stderr)
    asyncio.run(proxy.run())

if __name__ == "__main__":
    main()

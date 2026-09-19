# Changelog

## [2.0.0] — 2026-09-19

### Changed — breaking
- Removed the `mcp` SDK dependency entirely. The honeypot server and InjectShield
  proxy now implement the MCP stdio transport (newline-delimited JSON-RPC) in
  pure stdlib — the package has **zero dependencies**.
  - `PhantomSnareServer`: `run()` → `serve()`; tool defs are plain dicts instead
    of `mcp.types` objects.
  - `InjectShieldProxy`: upstream `initialize` is answered immediately while the
    downstream server handshakes in a background thread (was sequential/blocking).
  - Motivation: `import mcp` cost ~1.4s warm / ~12s cold under AV scanning,
    exceeding Claude Desktop's ~3.4s shared-pool initialize timeout for
    Cowork/Code sessions → `Error: Request timed out`.

### Added
- **SessionTracker** (`session.py`) — cross-call accumulation: kill-chain stages
  (recon → staging → exfil), persistent-probing / sustained-injection escalation
  floors, and call-velocity signals. Wired into both honeypot and shield paths.
- **Evasion normalization** — before pattern matching, arguments are decoded
  through: NFKC + Cyrillic/Greek confusable collapse, zero-width strip,
  URL-decode (2 passes), base64 token decode, ROT13, despaced letters, and
  leetspeak. Hits on transformed text are tagged (`InjectionHit.transform`),
  recorded in `fp.evasion_techniques`, and get a confidence bump — obfuscation
  is itself a signal.
- **5 new trap tools**: `list_directory`, `list_files`, `create_file`,
  `write_file`, `delete_file`. Directory listings are seeded with bait
  filenames to lure enumeration into the juicier traps.
- **Simulated latency** — per-tool response delays (`SIMULATED_LATENCY_MS`) so
  instant responses can't fingerprint the honeypot. Applied to shield blocks
  too. `PHANTOM_SNARE_LATENCY_SCALE` env var scales or disables (`0`).
- `HoneypotLogger.log_event()` public API; disk-failure-tolerant logging.
- New fingerprint fields: `evasion_techniques`, `session_call_index`,
  `session_escalation`.

### Fixed
- Logger and VIGIL queue `mkdir` failures no longer kill startup (previously a
  crash before the MCP handshake — indistinguishable from a timeout).
- InjectShield's block path called `logger.log_alert()`, which didn't exist —
  would have crashed on the first blocked call.
- OVERRIDE pattern now catches "ignore **all** previous instructions".
- 19 new tests (47 total).

## [1.0.0] — 2026-09-19

Initial release: honeypot + InjectShield proxy on the `mcp` SDK.

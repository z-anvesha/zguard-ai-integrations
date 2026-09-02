#!/usr/bin/env python3
"""
Zscaler AI Guard — MCP request scanner for OpenAI Codex CLI (PreToolUse: mcp__.*).

Scans MCP tool arguments with direction=IN before the call leaves Codex, catching
sensitive data on its way to a third-party MCP server and injected instructions in
tool parameters.

Exit 0 allows the call; exit 2 blocks it. Fail-closed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aiguard_utils import (  # noqa: E402
    EXIT_ALLOW,
    EXIT_BLOCK,
    derive_transaction_id,
    describe,
    extract_tool_input,
    log_message,
    read_hook_input,
    scan_content,
    truncate,
    verdict_blocks,
)


def main() -> int:
    data = read_hook_input()

    tool_name = str(data.get("tool_name") or "unknown")
    payload = extract_tool_input(data).strip()
    if not payload:
        return EXIT_ALLOW  # Nothing to scan.

    content = truncate(payload)
    log_message(f"Scanning MCP request {tool_name} ({len(content)} chars)")

    result = scan_content(content, "IN", derive_transaction_id(data))

    if result.get("error"):
        log_message(
            f"ERROR scanning MCP request {tool_name} (fail-closed): {result['error']}"
        )
        print(
            f"Zscaler AI Guard: scan failed — blocking MCP request (fail-closed): {result['error']}",
            file=sys.stderr,
        )
        return EXIT_BLOCK

    if verdict_blocks(result):
        log_message(f"BLOCKED MCP REQUEST {tool_name}: {describe(result)}")
        names = result.get("blocking_detectors") or result.get("triggered_detectors")
        detail = f"\nTriggered detectors: {', '.join(names)}" if names else ""
        print(
            f"Blocked by Zscaler AI Guard: MCP request to {tool_name} violates security policy."
            f"{detail}\nSeverity: {result.get('severity') or 'NONE'}"
            f" | Transaction ID: {result.get('transaction_id') or 'unknown'}",
            file=sys.stderr,
        )
        return EXIT_BLOCK

    if str(result.get("action", "")).upper() == "DETECT":
        log_message(f"DETECTED (monitor-only) MCP REQUEST {tool_name}: {describe(result)}")
    else:
        log_message(f"ALLOWED MCP REQUEST {tool_name}: {describe(result)}")
    return EXIT_ALLOW


if __name__ == "__main__":
    sys.exit(main())

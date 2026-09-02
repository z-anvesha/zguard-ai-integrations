#!/usr/bin/env python3
"""
Zscaler AI Guard — MCP response scanner for OpenAI Codex CLI (PostToolUse: mcp__.*).

Scans MCP tool output with direction=OUT before it reaches the model. This is the
main defense against indirect prompt injection: content fetched from an external
server is untrusted, and instructions hidden inside it would otherwise be read by
Codex as if the user had written them.

PostToolUse communicates through stdout JSON and always exits 0. A block emits
``{"continue": false, ...}``, halting the turn so the untrusted content is never
processed. Fail-closed.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aiguard_utils import (  # noqa: E402
    EXIT_ALLOW,
    MIN_SCAN_CHARS,
    derive_transaction_id,
    describe,
    extract_tool_output,
    log_message,
    read_hook_input,
    scan_content,
    truncate,
    verdict_blocks,
)


def block(message: str) -> int:
    """Halt the turn; PostToolUse always exits 0."""
    print(message, file=sys.stderr)
    sys.stdout.write(
        json.dumps(
            {
                "continue": False,
                "stopReason": "Zscaler AI Guard blocked MCP response",
                "systemMessage": message,
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": message,
                },
            }
        )
    )
    return EXIT_ALLOW


def main() -> int:
    data = read_hook_input()

    tool_name = str(data.get("tool_name") or "unknown")
    output = extract_tool_output(data)
    log_message(f"{tool_name}: extracted content length: {len(output)}")

    if len(output.strip()) < MIN_SCAN_CHARS:
        log_message(f"{tool_name}: skipping — insufficient content ({len(output)} chars)")
        return EXIT_ALLOW

    content = truncate(output)
    result = scan_content(content, "OUT", derive_transaction_id(data))

    if result.get("error"):
        log_message(
            f"ERROR scanning MCP response {tool_name} (fail-closed): {result['error']}"
        )
        return block(
            f"Zscaler AI Guard: scan of {tool_name} response failed — blocking "
            f"(fail-closed): {result['error']}"
        )

    if verdict_blocks(result):
        log_message(f"BLOCKED MCP RESPONSE {tool_name}: {describe(result)}")
        names = result.get("blocking_detectors") or result.get("triggered_detectors")
        detail = f" (detected: {', '.join(names)})" if names else ""
        return block(
            f"Blocked by Zscaler AI Guard: response from {tool_name} violates "
            f"security policy{detail} — severity={result.get('severity') or 'NONE'}"
            f" [txn:{result.get('transaction_id') or 'unknown'}]"
        )

    if str(result.get("action", "")).upper() == "DETECT":
        log_message(f"DETECTED (monitor-only) MCP RESPONSE {tool_name}: {describe(result)}")
    else:
        log_message(f"ALLOWED MCP RESPONSE {tool_name}: {describe(result)}")
    return EXIT_ALLOW


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Zscaler AI Guard — Bash command scanner for OpenAI Codex CLI (PreToolUse: Bash).

Scans the command with direction=IN before Codex executes it, catching destructive
commands, credential exfiltration, and injected shell payloads.

Exit 0 allows execution; exit 2 blocks it. Fail-closed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aiguard_utils import (  # noqa: E402
    EXIT_ALLOW,
    EXIT_BLOCK,
    derive_transaction_id,
    describe,
    log_message,
    read_hook_input,
    scan_content,
    truncate,
    verdict_blocks,
)


def main() -> int:
    data = read_hook_input()

    tool_input = data.get("tool_input")
    command = ""
    if isinstance(tool_input, dict):
        command = str(tool_input.get("command") or "").strip()
    elif isinstance(tool_input, str):
        command = tool_input.strip()

    if not command:
        return EXIT_ALLOW  # Nothing to scan.

    content = truncate(command)
    log_message(f"Scanning bash command: {content[:120]}")

    result = scan_content(content, "IN", derive_transaction_id(data))

    if result.get("error"):
        log_message(f"ERROR scanning bash command (fail-closed): {result['error']}")
        print(
            f"Zscaler AI Guard: scan failed — blocking command (fail-closed): {result['error']}",
            file=sys.stderr,
        )
        return EXIT_BLOCK

    if verdict_blocks(result):
        log_message(f"BLOCKED BASH COMMAND: {describe(result)} :: {content[:120]}")
        names = result.get("blocking_detectors") or result.get("triggered_detectors")
        detail = f"\nTriggered detectors: {', '.join(names)}" if names else ""
        print(
            "Blocked by Zscaler AI Guard: this command violates security policy."
            f"{detail}\nSeverity: {result.get('severity') or 'NONE'}"
            f" | Transaction ID: {result.get('transaction_id') or 'unknown'}",
            file=sys.stderr,
        )
        return EXIT_BLOCK

    if str(result.get("action", "")).upper() == "DETECT":
        log_message(f"DETECTED (monitor-only) BASH COMMAND: {describe(result)}")
    else:
        log_message(f"ALLOWED BASH COMMAND: {describe(result)}")
    return EXIT_ALLOW


if __name__ == "__main__":
    sys.exit(main())

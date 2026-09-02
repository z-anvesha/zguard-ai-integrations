#!/usr/bin/env python3
"""
Zscaler AI Guard — Bash output scanner for OpenAI Codex CLI (PostToolUse: Bash).

Scans command output with direction=OUT before it returns to the model, catching
secrets, credentials, and PII that a command surfaced from the filesystem or
environment.

PostToolUse communicates through stdout JSON and always exits 0. A block emits
``{"decision": "block", "reason": ...}``, which replaces the tool result with the
reason rather than hard-failing the turn — the model sees why the output was
withheld instead of the secret itself. Fail-closed.
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
    """Replace the tool result with feedback; PostToolUse always exits 0."""
    print(f"\n{message}\n", file=sys.stderr)
    sys.stdout.write(
        json.dumps(
            {
                "decision": "block",
                "reason": message,
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

    output = extract_tool_output(data)
    if len(output.strip()) < MIN_SCAN_CHARS:
        log_message(f"Bash: skipping — insufficient content ({len(output)} chars)")
        return EXIT_ALLOW

    content = truncate(output)
    log_message(f"Scanning bash output ({len(content)} chars)")

    result = scan_content(content, "OUT", derive_transaction_id(data))

    if result.get("error"):
        log_message(f"ERROR scanning bash output (fail-closed): {result['error']}")
        return block(
            "Zscaler AI Guard: scan failed — withholding command output "
            f"(fail-closed): {result['error']}"
        )

    if verdict_blocks(result):
        log_message(f"BLOCKED BASH OUTPUT: {describe(result)}")
        names = result.get("blocking_detectors") or result.get("triggered_detectors")
        detail = f" (detected: {', '.join(names)})" if names else ""
        return block(
            "Blocked by Zscaler AI Guard: command output violates security policy"
            f"{detail} — severity={result.get('severity') or 'NONE'}"
            f" [txn:{result.get('transaction_id') or 'unknown'}]"
        )

    if str(result.get("action", "")).upper() == "DETECT":
        log_message(f"DETECTED (monitor-only) BASH OUTPUT: {describe(result)}")
    else:
        log_message(f"ALLOWED BASH OUTPUT: {describe(result)}")
    return EXIT_ALLOW


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Zscaler AI Guard — user prompt scanner for OpenAI Codex CLI (UserPromptSubmit).

Scans the prompt with direction=IN before it reaches the model, giving first-line
defense against prompt injection, secrets, PII, and toxic content.

Exit 0 allows the prompt; exit 2 blocks it. Fail-closed.
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

    prompt = str(data.get("prompt") or "").strip()
    if not prompt:
        return EXIT_ALLOW  # Nothing to scan.

    content = truncate(prompt)
    log_message(f"Scanning user input ({len(content)} chars): {content[:80]}...")

    result = scan_content(content, "IN", derive_transaction_id(data))

    if result.get("error"):
        log_message(f"ERROR scanning user input (fail-closed): {result['error']}")
        print(
            f"Zscaler AI Guard: scan failed — blocking prompt (fail-closed): {result['error']}",
            file=sys.stderr,
        )
        return EXIT_BLOCK

    if verdict_blocks(result):
        log_message(f"BLOCKED USER INPUT: {describe(result)}")
        detail = ""
        if result.get("blocking_detectors") or result.get("triggered_detectors"):
            names = result["blocking_detectors"] or result["triggered_detectors"]
            detail = f"\nTriggered detectors: {', '.join(names)}"
        print(
            "Blocked by Zscaler AI Guard: your input violates security policy."
            f"{detail}\nSeverity: {result.get('severity') or 'NONE'}"
            f" | Transaction ID: {result.get('transaction_id') or 'unknown'}",
            file=sys.stderr,
        )
        return EXIT_BLOCK

    if str(result.get("action", "")).upper() == "DETECT":
        log_message(f"DETECTED (monitor-only) USER INPUT: {describe(result)}")
    else:
        log_message(f"ALLOWED USER INPUT: {describe(result)}")
    return EXIT_ALLOW


if __name__ == "__main__":
    sys.exit(main())

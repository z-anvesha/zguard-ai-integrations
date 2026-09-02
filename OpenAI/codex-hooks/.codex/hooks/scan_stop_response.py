#!/usr/bin/env python3
"""
Zscaler AI Guard — final response scanner for OpenAI Codex CLI (Stop).

Scans the assistant's final message with direction=OUT after streaming completes,
catching data leakage and unsafe content in what the model produced.

The Stop event uses a JSON contract rather than exit codes: this hook always exits
0 and prints {"continue": false, "stopReason": ...} to halt the session, or
{"continue": true} to let it finish. Because the response has already been
displayed by the time Stop fires, this is detect-and-halt, not prevention — the
UserPromptSubmit and PreToolUse hooks are the preventive controls.

For the same reason this hook alone fails **open**: a BLOCK verdict still halts the
session, but a scan error lets the turn finish rather than breaking the session
over content the user has already seen.
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
    log_message,
    read_hook_input,
    scan_content,
    truncate,
    verdict_blocks,
)


def emit(payload: dict) -> int:
    """Stop hooks communicate through stdout JSON; always exit 0."""
    sys.stdout.write(json.dumps(payload))
    return EXIT_ALLOW


def main() -> int:
    data = read_hook_input()

    # Codex sets stop_hook_active while a previous Stop hook is still unwinding.
    # Scanning again there would recurse, so let the turn finish.
    if data.get("stop_hook_active"):
        return emit({"continue": True})

    message = str(data.get("last_assistant_message") or "").strip()
    if len(message) < MIN_SCAN_CHARS:
        return emit({"continue": True})

    content = truncate(message)
    log_message(f"Scanning Codex final response ({len(content)} chars)")

    result = scan_content(content, "OUT", derive_transaction_id(data))

    if result.get("error"):
        # Fail-open here, unlike every other hook. The response has already been
        # streamed and displayed, so halting on a transient scan failure protects
        # nothing and only breaks the session. The error is logged for audit.
        log_message(f"ERROR scanning final response (fail-open): {result['error']}")
        return emit({"continue": True})

    if verdict_blocks(result):
        log_message(f"BLOCKED CODEX RESPONSE: {describe(result)}")
        names = result.get("blocking_detectors") or result.get("triggered_detectors")
        detail = f" (detectors: {', '.join(names)})" if names else ""
        return emit(
            {
                "continue": False,
                "stopReason": (
                    "Zscaler AI Guard blocked the response: severity="
                    f"{result.get('severity') or 'NONE'}{detail}"
                    f" [txn:{result.get('transaction_id') or 'unknown'}]"
                ),
            }
        )

    if str(result.get("action", "")).upper() == "DETECT":
        log_message(f"DETECTED (monitor-only) CODEX RESPONSE: {describe(result)}")
    else:
        log_message(f"ALLOWED CODEX RESPONSE: {describe(result)}")
    return emit({"continue": True})


if __name__ == "__main__":
    sys.exit(main())

"""
Zscaler AI Guard — shared utilities for OpenAI Codex CLI hooks.

Every hook in this directory funnels through :func:`scan_content`, which calls the
AI Guard policy detection API via ``zscaler-sdk-python``:

    from zscaler.oneapi_client import LegacyAIGuardClient

    with LegacyAIGuardClient({"api_key": ..., "cloud": ..., "timeout": ...}) as client:
        client.aiguard.policy_detection.resolve_and_execute_policy(...)

Requires zscaler-sdk-python >= 1.9.44. Earlier releases never attached the Bearer
token to AI Guard legacy calls, so every scan failed with a 401.

Enforcement is fail-closed: misconfiguration, API errors, and unrecognized verdicts
all block. Codex hook scripts translate that into the exit code or JSON their
particular event expects.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Codex ids (turn_id, tool_use_id, session_id) are arbitrary strings, but the AI
# Guard API rejects a transactionId that is not a standard 36-char UUID with a 500.
# Hashing them into this namespace keeps the mapping deterministic, so the same
# Codex turn always yields the same transaction id and stays correlatable.
_TRANSACTION_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "zscaler-aiguard/codex-hooks")

# Codex hook exit codes: 0 lets the event proceed, 2 blocks it.
EXIT_ALLOW = 0
EXIT_BLOCK = 2

# AI Guard accepts large payloads, but Codex tool output can be unbounded.
MAX_SCAN_CHARS = 20000

# Content shorter than this is noise (empty dicts, "ok", exit statuses).
MIN_SCAN_CHARS = 5


def _hooks_dir() -> Path:
    """Directory holding the hook scripts (.codex/hooks/)."""
    return Path(__file__).resolve().parent


def _integration_root() -> Path:
    """codex-hooks/ — the directory containing .codex/."""
    return _hooks_dir().parent.parent


def env_candidates() -> list[Path]:
    """
    Every location searched for a .env file, in priority order.

    The canonical spot is next to the .codex/ directory — that is the project root
    Codex is launched from. The others are accepted because putting the file
    "somewhere under .codex/" is an easy and reasonable mistake to make.
    """
    seen: list[Path] = []
    for path in (
        _integration_root() / ".env",  # canonical: next to .codex/
        Path.cwd() / ".env",
        _hooks_dir().parent / ".env",  # .codex/.env
        _hooks_dir() / ".env",  # .codex/hooks/.env
    ):
        if path not in seen:
            seen.append(path)
    return seen


def _load_dotenv() -> None:
    """
    Load AIGUARD_* variables from .env files.

    Checked in order; the first definition wins, and real environment variables
    always take precedence. Values may be quoted or bare.
    """
    for env_path in env_candidates():
        if not env_path.is_file():
            continue
        try:
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Tolerate "export KEY=value" as written in shell-style .env files.
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and value and key not in os.environ:
                    os.environ[key] = value
        except OSError:
            continue


_load_dotenv()


def get_log_file() -> Path:
    """
    Resolve the security log path.

    ``~`` is expanded even when supplied through SECURITY_LOG_PATH; using the value
    verbatim would create a directory literally named "~" in Codex's working
    directory and hide every log line there.
    """
    raw = os.environ.get("SECURITY_LOG_PATH") or str(_hooks_dir() / "aiguard.log")
    log_file = Path(os.path.expanduser(raw))
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return log_file


def log_message(message: str) -> None:
    """Append a timestamped line to the security log; never raise into the hook."""
    try:
        with open(get_log_file(), "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except OSError:
        pass


def get_client_config() -> dict[str, Any]:
    """
    Build the LegacyAIGuardClient config.

    Only api_key, cloud and timeout are read by the client; other keys are
    silently discarded, so nothing else is passed.
    """
    cloud = os.environ.get("AIGUARD_CLOUD", "us1").strip() or "us1"
    try:
        timeout = int(os.environ.get("AIGUARD_TIMEOUT", "30"))
    except ValueError:
        timeout = 30
    return {
        "api_key": os.environ.get("AIGUARD_API_KEY", "").strip(),
        "cloud": cloud,
        "timeout": timeout,
    }


def get_policy_id() -> Optional[int]:
    """
    Explicit policy ID, if configured.

    Leaving this unset is preferred: the API then resolves the policy bound to the
    API key. A stale ID silently pins scanning to the wrong policy.
    """
    raw = os.environ.get("AIGUARD_POLICY_ID", "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def get_triggered_detectors(detector_responses: Any) -> list[str]:
    """Names of detectors that fired, whatever action they carried."""
    if not detector_responses:
        return []
    return [
        name
        for name, det in detector_responses.items()
        if getattr(det, "triggered", False)
    ]


def get_blocking_detectors(detector_responses: Any) -> list[str]:
    """Names of detectors that returned a BLOCK action."""
    if not detector_responses:
        return []
    return [
        name
        for name, det in detector_responses.items()
        if str(getattr(det, "action", "") or "").upper() == "BLOCK"
    ]


def as_api_transaction_id(raw: Optional[str]) -> Optional[str]:
    """
    Coerce a Codex identifier into the UUID the API demands.

    A value that is already a UUID is passed through unchanged; anything else is
    hashed deterministically. Returns None for empty input so the API assigns its
    own id.
    """
    if not raw:
        return None
    raw = str(raw).strip()
    if not raw:
        return None
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(_TRANSACTION_NAMESPACE, raw))


def scan_content(
    content: str,
    direction: str,
    transaction_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Scan one piece of content through AI Guard.

    Args:
        content: Text to scan.
        direction: "IN" for prompts and tool inputs, "OUT" for model/tool output.
        transaction_id: Codex turn or session id, echoed back by the API so a
            verdict can be traced to the turn that produced it.

    Returns a dict with action/severity/policy/detector fields. ``error`` is set
    when the scan could not be completed; callers must treat that as a block.
    """
    result: dict[str, Any] = {
        "action": "ALLOW",
        "severity": None,
        "transaction_id": None,
        "policy_name": None,
        "triggered_detectors": [],
        "blocking_detectors": [],
        "error": None,
    }

    config = get_client_config()
    if not config["api_key"]:
        result["error"] = "AIGUARD_API_KEY not set"
        return result

    try:
        from zscaler.oneapi_client import LegacyAIGuardClient
    except ImportError:
        result["error"] = (
            "zscaler-sdk-python not installed. Run: pip install 'zscaler-sdk-python>=1.9.44'"
        )
        return result

    policy_id = get_policy_id()
    api_transaction_id = as_api_transaction_id(transaction_id)

    try:
        with LegacyAIGuardClient(config) as client:
            detection = client.aiguard.policy_detection
            if policy_id is not None:
                api_result, _resp, error = detection.execute_policy(
                    content=content,
                    direction=direction,
                    policy_id=policy_id,
                    transaction_id=api_transaction_id,
                )
            else:
                api_result, _resp, error = detection.resolve_and_execute_policy(
                    content=content,
                    direction=direction,
                    transaction_id=api_transaction_id,
                )

            if error:
                result["error"] = str(error)
                return result

            # Fail closed on a null action: the API answers 200 with an in-body
            # statusCode for soft failures such as "Policy not found", and
            # defaulting that to ALLOW would silently disable scanning.
            if not api_result.action:
                result["error"] = "scan returned no action verdict (%s)" % (
                    getattr(api_result, "error_msg", None)
                    or "statusCode=%s" % getattr(api_result, "status_code", None))
                return result
            result["action"] = str(api_result.action).upper()
            result["severity"] = getattr(api_result, "severity", None)
            result["transaction_id"] = getattr(api_result, "transaction_id", None)
            result["policy_name"] = getattr(api_result, "policy_name", None)
            detectors = getattr(api_result, "detector_responses", None)
            result["triggered_detectors"] = get_triggered_detectors(detectors)
            result["blocking_detectors"] = get_blocking_detectors(detectors)

    except Exception as exc:  # noqa: BLE001 - any failure must fail closed
        result["error"] = str(exc)

    return result


def verdict_blocks(result: dict[str, Any]) -> bool:
    """
    Decide whether a scan result should stop the event.

    Fail-closed: an error blocks. BLOCK blocks. ALLOW and DETECT proceed — DETECT
    is AI Guard's monitor-only verdict and is logged by the caller. Any verdict
    the integration does not recognize blocks rather than being assumed safe.
    """
    if result.get("error"):
        return True
    return str(result.get("action", "")).upper() not in ("ALLOW", "DETECT")


def describe(result: dict[str, Any]) -> str:
    """One-line verdict summary for the log and for user-facing block messages."""
    parts = [f"action={result.get('action')}"]
    if result.get("severity"):
        parts.append(f"severity={result['severity']}")
    if result.get("policy_name"):
        parts.append(f"policy={result['policy_name']}")
    if result.get("transaction_id"):
        parts.append(f"txn={result['transaction_id']}")
    if result.get("blocking_detectors"):
        parts.append(f"blocking=[{','.join(result['blocking_detectors'])}]")
    elif result.get("triggered_detectors"):
        parts.append(f"triggered=[{','.join(result['triggered_detectors'])}]")
    return ", ".join(parts)


def read_hook_input() -> dict[str, Any]:
    """Read the hook event JSON from stdin; an unparsable body yields {}."""
    import sys

    try:
        raw = sys.stdin.read()
    except (OSError, ValueError):
        return {}
    if not raw or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def derive_session_id(data: dict[str, Any]) -> str:
    """
    Stable identifier for the conversation.

    Codex supplies session_id directly. Older payloads only carry transcript_path,
    from which the session segment is recovered; failing that, the working
    directory is hashed so a session still groups consistently.
    """
    session_id = str(data.get("session_id") or "").strip()
    if session_id:
        return session_id

    transcript = str(data.get("transcript_path") or "").strip()
    if transcript:
        match = re.search(r"/sessions/([^/]+)/", transcript)
        if match:
            return match.group(1)
        return hashlib.md5(transcript.encode("utf-8")).hexdigest()

    return hashlib.md5(os.getcwd().encode("utf-8")).hexdigest()


def derive_transaction_id(data: dict[str, Any]) -> str:
    """
    Identifier for this specific turn, preferred over the session id.

    turn_id changes per turn and tool_use_id per tool call, so either pinpoints the
    event far better than the session; the session id is the last resort.
    """
    for key in ("turn_id", "tool_use_id"):
        value = str(data.get(key) or "").strip()
        if value:
            return value
    return derive_session_id(data)


def truncate(text: str) -> str:
    """Cap content at the scan limit."""
    return text if len(text) <= MAX_SCAN_CHARS else text[:MAX_SCAN_CHARS]


def stringify(value: Any) -> str:
    """Render an arbitrary hook payload value as scannable text."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def collect_strings(value: Any, max_depth: int = 6, max_items: int = 50) -> str:
    """
    Pull every string out of a nested tool payload, space-joined.

    Mirrors the shell hooks' ``jq '.. | strings'`` fallback: tool responses vary
    wildly in shape, and the goal is to scan whatever text they carry rather than
    to model each tool's schema.
    """
    found: list[str] = []

    def walk(node: Any, depth: int) -> None:
        if depth > max_depth or len(found) >= max_items:
            return
        if isinstance(node, str):
            if node.strip():
                found.append(node)
        elif isinstance(node, dict):
            for item in node.values():
                walk(item, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)

    walk(value, 0)
    return " ".join(found).strip()


def extract_tool_output(data: dict[str, Any]) -> str:
    """
    Get the text of a tool result from a PostToolUse payload.

    Tries the common explicit fields first, then falls back to harvesting every
    string in the object, then to a raw dump — the same escalation the shell hooks
    used, so no tool's output silently escapes scanning.
    """
    response = data.get("tool_response")
    if response is None:
        response = data.get("tool_output")
    if response is None:
        return ""

    if isinstance(response, str):
        return response

    if isinstance(response, dict):
        for field in ("output", "stdout", "content", "text", "result", "data"):
            value = response.get(field)
            if isinstance(value, str) and len(value.strip()) >= MIN_SCAN_CHARS:
                return value
        harvested = collect_strings(response)
        if len(harvested) >= MIN_SCAN_CHARS:
            return harvested

    harvested = collect_strings(response)
    return harvested if harvested else stringify(response)


def extract_tool_input(data: dict[str, Any]) -> str:
    """Get scannable text from a PreToolUse payload's tool_input."""
    tool_input = data.get("tool_input")
    if tool_input is None:
        return ""
    if isinstance(tool_input, str):
        return tool_input
    if isinstance(tool_input, dict):
        for field in ("command", "query", "prompt", "message", "content", "body", "url"):
            value = tool_input.get(field)
            if isinstance(value, str) and value.strip():
                return value
    return stringify(tool_input)


def _self_check() -> int:
    """
    Diagnose configuration: where .env was looked for, what was found, and whether
    a live scan succeeds. Run with: python3 .codex/hooks/aiguard_utils.py
    """
    import sys

    print("Zscaler AI Guard — Codex hooks configuration check\n")
    print(f"hook scripts : {_hooks_dir()}")
    print(f"project root : {_integration_root()}   <- .env belongs here")
    print(f"working dir  : {Path.cwd()}\n")

    print(".env search order:")
    found_any = False
    for path in env_candidates():
        if path.is_file():
            print(f"  [FOUND]   {path}")
            found_any = True
        else:
            print(f"  [missing] {path}")
    if not found_any:
        print("\n  No .env found. Create one next to the .codex/ directory:")
        print(f"    echo 'AIGUARD_API_KEY=your-key' > {_integration_root() / '.env'}")
        print("  (or export AIGUARD_API_KEY in the shell that launches codex)")

    config = get_client_config()
    key = config["api_key"]
    print(f"\nAIGUARD_API_KEY : {'set (' + str(len(key)) + ' chars)' if key else 'NOT SET'}")
    print(f"AIGUARD_CLOUD   : {config['cloud']}")
    print(f"AIGUARD_TIMEOUT : {config['timeout']}")
    policy = get_policy_id()
    print(f"AIGUARD_POLICY_ID: {policy if policy is not None else 'unset (auto-resolve — recommended)'}")

    if not key:
        print("\nRESULT: hooks will fail closed and block every prompt.")
        return 1

    print("\nRunning a live test scan...")
    result = scan_content("hello", "IN", "config-check")
    if result.get("error"):
        print(f"RESULT: scan FAILED — {result['error']}")
        print("        hooks will fail closed and block every prompt.")
        return 1

    print(f"RESULT: scan succeeded — {describe(result)}")
    if verdict_blocks(result):
        print("\n  NOTE: the policy blocked the word 'hello'. The hooks are working,")
        print("  but this policy will block every prompt you type into Codex.")
        print("  Fix the rule in the AI Guard Console to block on detector hits.")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(_self_check())

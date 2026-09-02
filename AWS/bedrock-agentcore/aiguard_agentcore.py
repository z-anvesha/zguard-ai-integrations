"""
Zscaler AI Guard guard for Amazon Bedrock AgentCore agents.

Unlike the SDK-client hooks, an AgentCore agent is *your* loop: the runtime hosts
the code you wrote, and there is no universal seam to intercept an arbitrary agent
loop. So this integration is a guard you call at the four legs of that loop:

    before-model   scan the prompt going to the model
    after-model    scan the model's response
    before-tool    scan a tool call's input   (as a first-class tool_event)
    after-tool     scan a tool call's output  (where injected tool results and
                   leaked credentials are actually caught)

This is the first seat that sees tool calls as tool calls. It is the deepest of
the AWS integrations and the narrowest in fit: you place the calls, and only the
loop you instrument is covered.

The guard pulls the AgentCore request id and session id from the runtime context
when it is available (so a scan in the AI Guard Console lines up with an
invocation in the AgentCore logs), and falls back to a generated id off-runtime.

Single file, standard library only. AgentCore runs Python, so no other SDK is
required to scan; boto3/Bedrock are only needed by your agent, not by the guard.

Environment variables (standard Zscaler AI Guard names):

    AIGUARD_API_KEY        required   API key from the AI Guard Console
    AIGUARD_CLOUD          optional   cloud region, defaults to us1
    AIGUARD_POLICY_ID      optional   pin one policy; unset lets the API auto-resolve
    AIGUARD_TIMEOUT        optional   request timeout in seconds, defaults to 30
    AIGUARD_OVERRIDE_URL   optional   full base URL, overrides AIGUARD_CLOUD

Usage (hand-rolled loop):

    from aiguard_agentcore import AIGuardGuard

    guard = AIGuardGuard(app_name="support-agent", agent_arn=MY_AGENT_ARN)

    guard.scan_prompt(user_text)                 # raises AIGuardBlocked on block
    reply = model_call(user_text)
    guard.scan_response(reply, prompt=user_text)

    guard.scan_tool_input(name, args)            # before running a tool
    result = run_tool(name, args)
    guard.scan_tool_output(name, args, result)   # before feeding it back to the model

Usage (wrap a tool so both legs are automatic):

    @guard.guard_tool(server_name="crm")
    def read_ticket(ticket_id: str) -> str:
        ...

The wrapper matches the tool it decorates: an async tool is awaited and a
generator tool is drained before the output leg scans, so that leg always sees
what the tool produced rather than a coroutine or generator object.
"""

import asyncio
import functools
import inspect
import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid

logger = logging.getLogger("aiguard")
if logger.level == logging.NOTSET:
    logger.setLevel(logging.INFO)

DEFAULT_CLOUD = "us1"
RESOLVE_PATH = "/v1/detection/resolve-and-execute-policy"
EXECUTE_PATH = "/v1/detection/execute-policy"

# Request ids and caller-supplied session strings are not UUIDs, which the API
# requires for transactionId; hash them into this namespace deterministically.
_TRANSACTION_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "zscaler-aiguard/aws-agentcore")

# Repo convention: app_name identifies the integration, and users append their
# own application name after it ("AWS-AgentCore-support-agent").
APP_NAME_PREFIX = "AWS-AgentCore"

# The scan API accepts exactly one tool ecosystem today: "mcp". Every other
# value (agentcore, python, custom, ...) is rejected with HTTP 400
# "unsupported ecosystem" -- measured against the live service, 2026-08-18.
TOOL_ECOSYSTEM = "mcp"


class AIGuardBlocked(Exception):
    """Raised by a guard leg when a scan verdict blocks."""

    def __init__(self, leg, verdict, transaction_id, detail=None):
        self.leg = leg
        self.verdict = verdict
        self.transaction_id = transaction_id
        self.detail = detail or {}
        super().__init__(
            "blocked by Zscaler AI Guard on the %s leg (detectors=%s transaction_id=%s transaction_id=%s)"
            % (leg, (", ".join(verdict.get("blocking_detectors") or verdict.get("triggered_detectors") or []) or verdict.get("reason") or "policy"), verdict.get("transaction_id"), transaction_id)
        )


# --------------------------------------------------------------------------
# runtime context (optional -- present only inside AgentCore)
# --------------------------------------------------------------------------

def _runtime_ids():
    """(request_id, session_id) from the AgentCore runtime context, or (None, None)."""
    try:
        from bedrock_agentcore.runtime import BedrockAgentCoreContext
    except Exception:
        return None, None
    try:
        return BedrockAgentCoreContext.get_request_id(), BedrockAgentCoreContext.get_session_id()
    except Exception:
        return None, None


def _runtime_agent_arn():
    """The runtime's own agent ARN, recovered the way the SDK does -- from
    cloud.resource_id in OTEL_RESOURCE_ATTRIBUTES. Returns None off-runtime.
    (The runtime injects this; there is no BEDROCK_AGENTCORE_AGENT_ARN env var.)"""
    attrs = os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "")
    for pair in attrs.split(","):
        key, _, value = pair.partition("=")
        if key.strip() == "cloud.resource_id" and value.strip():
            arn = value.strip()
            # OTEL sets this to either a runtime ARN or a runtime-endpoint ARN;
            # the SDK normalizes the endpoint form to the plain runtime ARN, and
            # so must we, or an exact-match join on the ARN the AgentCore console
            # shows will miss every scan this guard reports.
            if "/runtime-endpoint/" in arn:
                arn = arn.split("/runtime-endpoint/")[0]
            return arn
    return None


# --------------------------------------------------------------------------
# the scan call (identical hardening to the other AWS integrations)
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would re-send the Bearer key to whatever host the 3xx names; refuse."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())

# urlopen(timeout=) is a per-recv timeout that resets on every successful read,
# so a peer that trickles bytes can hold the caller far past `timeout`. The body
# is read against one wall-clock deadline, and capped at 10 MB so a runaway
# response cannot be buffered into the agent's memory.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_READ_CHUNK = 65536


def _read_bounded(resp, deadline):
    """Read a response body under a total deadline and a size cap.

    read1() hands back whatever one recv delivered, where read() keeps looping
    on the socket until the chunk is full. Taking one recv at a time and
    checking the clock between them is what bounds the whole read to the
    configured timeout plus at most one recv.
    """
    read_once = getattr(resp, "read1", None) or resp.read
    chunks = []
    total = 0
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("AI Guard response exceeded the scan deadline")
        chunk = read_once(_READ_CHUNK)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            raise ValueError("AI Guard response exceeded %d bytes" % _MAX_RESPONSE_BYTES)
        chunks.append(chunk)



def _default_timeout():
    """Request timeout in seconds; AIGUARD_TIMEOUT overrides the default."""
    try:
        return float(os.environ.get("AIGUARD_TIMEOUT", "").strip() or 30.0)
    except ValueError:
        return 30.0


def _default_endpoint():
    """Base URL for the tenant's cloud; AIGUARD_OVERRIDE_URL wins when set."""
    override = os.environ.get("AIGUARD_OVERRIDE_URL", "").strip()
    if override:
        return override
    cloud = os.environ.get("AIGUARD_CLOUD", "").strip() or DEFAULT_CLOUD
    return "https://api.%s.zseclipse.net" % cloud


def _resolve_policy_id(explicit=None):
    """Explicit policy id, else AIGUARD_POLICY_ID, else None for auto-resolve.

    Unset is the recommended posture: the API then resolves the policy bound to
    the API key. A stale explicit id silently pins scanning to the wrong policy.
    """
    raw = explicit if explicit is not None else os.environ.get("AIGUARD_POLICY_ID")
    if isinstance(raw, str):
        raw = raw.strip().strip('"').strip("'")
    if raw in (None, ""):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _as_transaction_id(raw):
    """Coerce an arbitrary id into the UUID the API requires.

    AI Guard rejects a transactionId that is not a standard 36-character UUID
    with an HTTP 500, and callers pass request ids and session strings. Hashing
    keeps the mapping deterministic, so the same call always reports the same
    transaction id and stays correlatable in the console.
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


# Legs map onto AI Guard's two directions: IN is content heading into the model
# (user prompts, and the tool arguments the model produced), OUT is content
# coming back out of it (model responses, and tool results fed back in).
_LEG_DIRECTION = {
    "prompt": "IN",
    "tool_input": "IN",
    "response": "OUT",
    "tool_output": "OUT",
}


def _leg_payload(leg, contents):
    """Flatten a leg's content list into (text, direction) for the scan API.

    The upstream shape is a list of one-key dicts -- {"prompt": ...},
    {"response": ...} or {"tool_event": {...}}. AI Guard scans a single string
    per call, so a tool_event is serialized whole: its arguments and result are
    exactly what an injection would hide in.
    """
    direction = _LEG_DIRECTION.get(leg, "IN")
    parts = []
    for item in (contents or []):
        if isinstance(item, str):
            parts.append(item)
            continue
        if not isinstance(item, dict):
            continue
        for key in ("prompt", "response", "tool_event"):
            if key not in item:
                continue
            value = item[key]
            parts.append(value if isinstance(value, str)
                         else json.dumps(value, ensure_ascii=False, sort_keys=True))
    return ("\n".join(p for p in parts if p), direction)


def _normalize_verdict(parsed):
    """Fold an AI Guard response into the verdict shape the legs consume.

    `action` is lowercased to allow/block. DETECT is AI Guard's monitor-only
    verdict: it is reported and logged but does not block, so it maps to allow.
    """
    action = str(parsed.get("action") or "").upper()
    detectors = parsed.get("detectorResponses") or {}
    triggered, blocking = [], []
    if isinstance(detectors, dict):
        for name, det in detectors.items():
            if not isinstance(det, dict):
                continue
            if det.get("triggered"):
                triggered.append(name)
            if str(det.get("action") or "").upper() == "BLOCK":
                blocking.append(name)
    return {
        "action": "block" if action == "BLOCK" else "allow" if action in ("ALLOW", "DETECT") else action.lower(),
        "raw_action": action,
        "severity": parsed.get("severity"),
        "policy_name": parsed.get("policyName"),
        "transaction_id": parsed.get("transactionId"),
        "triggered_detectors": triggered,
        "blocking_detectors": blocking,
        "error_msg": parsed.get("errorMsg"),
        # The API answers 200 with an in-body statusCode for soft failures such as
        # "Policy not found"; without it a bad policy id looks like an empty verdict.
        "status_code": parsed.get("statusCode"),
    }


def _scan(endpoint, api_key, payload, timeout, policy_id=None):
    if not endpoint.lower().startswith("https://"):
        return None, "refusing non-HTTPS endpoint: %s" % endpoint
    url = endpoint.rstrip("/") + (EXECUTE_PATH if policy_id is not None else RESOLVE_PATH)
    # One wall-clock budget for the whole call, not one per socket read. Hoisted
    # out of the try so the error path can read its diagnostic body under it too.
    deadline = time.monotonic() + timeout
    try:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer %s" % api_key,
            },
            method="POST")
        with _OPENER.open(request, timeout=timeout) as resp:
            parsed = json.loads(_read_bounded(resp, deadline).decode("utf-8"))
        if not isinstance(parsed, dict):
            return None, "unexpected scan response shape: %s" % type(parsed).__name__
        return _normalize_verdict(parsed), None
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = _read_bounded(exc, deadline).decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        return None, "HTTP %s from AI Guard: %s" % (exc.code, body)
    except urllib.error.URLError as exc:
        return None, "network error reaching AI Guard: %s" % exc.reason
    except Exception as exc:
        return None, "scan failed: %s" % exc


# --------------------------------------------------------------------------
# the guard
# --------------------------------------------------------------------------

class AIGuardGuard:
    """Scans the four legs of an AgentCore agent loop with Zscaler AI Guard.

    app_name        appended to "AWS-AgentCore-" in metadata.app_name.
    policy_id      pin one policy id; omit to let the API auto-resolve the
                   policy bound to the API key (recommended).
    agent_arn       stamped into metadata.agent_meta.agent_arn.
    agent_id / agent_version  optional agent_meta fields.
    app_user        end-user identity for metadata.app_user.
    ai_model        model id for metadata.ai_model.
    on_error        "block" (default) or "allow" when AI Guard is unreachable / errors.
    on_unscannable  "block" (default) or "allow" when there is no text to scan.
    strict_verdict  treat a detection-service timeout/error verdict as on_error.
    on_verdict      callable(leg, verdict) observer for every scan.
    timeout         seconds per scan call.

    Each scan_* method returns the verdict dict on allow and raises
    AIGuardBlocked on block (unless on_error/on_unscannable relax it).
    """

    def __init__(self, app_name=None, policy_id=None,
                 agent_arn=None, agent_id=None, agent_version=None,
                 app_user=None, ai_model=None, on_error="block",
                 on_unscannable="block", strict_verdict=False,
                 on_verdict=None, timeout=10.0):
        if on_error not in ("block", "allow"):
            raise ValueError('on_error must be "block" or "allow"')
        if on_unscannable not in ("block", "allow"):
            raise ValueError('on_unscannable must be "block" or "allow"')
        self.app_name = app_name
        self.policy_id = _resolve_policy_id(policy_id)
        self.agent_meta = {}
        resolved_arn = agent_arn or _runtime_agent_arn()
        if resolved_arn:
            self.agent_meta["agent_arn"] = resolved_arn
        if agent_id:
            self.agent_meta["agent_id"] = agent_id
        if agent_version:
            self.agent_meta["agent_version"] = agent_version
        self.app_user = app_user
        self.ai_model = ai_model
        self.on_error = on_error
        self.on_unscannable = on_unscannable
        self.strict_verdict = strict_verdict
        self.on_verdict = on_verdict
        self.timeout = timeout

    # -- public legs ------------------------------------------------------

    def scan_prompt(self, prompt, session_id=None, transaction_id=None):
        return self._text_leg("prompt", {"prompt": _as_text(prompt)},
                              session_id, transaction_id)

    def scan_response(self, response, prompt=None, context=None,
                      session_id=None, transaction_id=None):
        contents = {"response": _as_text(response)}
        if prompt:
            contents["prompt"] = _as_text(prompt)
        if context:
            contents["context"] = _as_text(context)
        return self._text_leg("response", contents, session_id, transaction_id)

    def scan_tool_input(self, tool_name, tool_input, server_name="agent-tools",
                        session_id=None, transaction_id=None):
        return self._tool_leg("tool_input", tool_name, tool_input, None,
                             server_name, session_id, transaction_id)

    def scan_tool_output(self, tool_name, tool_input, tool_output,
                         server_name="agent-tools", session_id=None, transaction_id=None):
        return self._tool_leg("tool_output", tool_name, tool_input, tool_output,
                             server_name, session_id, transaction_id)

    def guard_tool(self, server_name="agent-tools"):
        """Decorator: scan a tool function's input before it runs and its output
        before it returns, so both tool legs are automatic. The wrapper matches
        the tool it decorates -- an async tool is awaited and a generator tool is
        drained before the output leg scans, so that leg never scans a coroutine
        or generator object and reports it as inspected."""
        def decorator(fn):
            try:
                sig = inspect.signature(fn)
            except (ValueError, TypeError):
                sig = None
            tool_name = getattr(fn, "__name__", "tool")

            def bind_input(args, kwargs):
                # Bind to parameter NAMES so the scanned input reads as data
                # ({"ticket_id": "T-1"}), not as Python call structure
                # ({"args": [...], "kwargs": {...}}) -- the latter trips a
                # source-code detector on every guarded call.
                if sig is None:
                    return {"args": list(args), "kwargs": dict(kwargs)}
                try:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    tool_input = dict(bound.arguments)
                except TypeError:
                    return {"args": list(args), "kwargs": dict(kwargs)}
                # Drop a receiver (self/cls) so a bound object's repr --
                # possibly carrying connection strings or secrets --
                # never reaches the scan payload or the logs.
                first = next(iter(sig.parameters), None)
                if first in ("self", "cls"):
                    tool_input.pop(first, None)
                return tool_input

            # A scan is a blocking urllib call, so the async wrappers offload it
            # to a worker thread instead of parking the runtime's event loop
            # (asyncio.to_thread carries the context, so the AgentCore request
            # and session ids still resolve inside the scan).
            if inspect.isasyncgenfunction(fn):
                @functools.wraps(fn)
                async def wrapper(*args, **kwargs):
                    tool_input = bind_input(args, kwargs)
                    await asyncio.to_thread(self.scan_tool_input, tool_name, tool_input,
                                            server_name=server_name)
                    items = [item async for item in fn(*args, **kwargs)]
                    await asyncio.to_thread(self.scan_tool_output, tool_name, tool_input,
                                            items, server_name=server_name)
                    for item in items:
                        yield item
            elif inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def wrapper(*args, **kwargs):
                    tool_input = bind_input(args, kwargs)
                    await asyncio.to_thread(self.scan_tool_input, tool_name, tool_input,
                                            server_name=server_name)
                    result = await fn(*args, **kwargs)
                    if _is_lazy(result):
                        return self._unscannable_tool_output(tool_name, result)
                    await asyncio.to_thread(self.scan_tool_output, tool_name, tool_input,
                                            result, server_name=server_name)
                    return result
            elif inspect.isgeneratorfunction(fn):
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    tool_input = bind_input(args, kwargs)
                    self.scan_tool_input(tool_name, tool_input, server_name=server_name)
                    items = list(fn(*args, **kwargs))
                    self.scan_tool_output(tool_name, tool_input, items, server_name=server_name)
                    for item in items:
                        yield item
            else:
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    tool_input = bind_input(args, kwargs)
                    self.scan_tool_input(tool_name, tool_input, server_name=server_name)
                    result = fn(*args, **kwargs)
                    if _is_lazy(result):
                        return self._unscannable_tool_output(tool_name, result)
                    self.scan_tool_output(tool_name, tool_input, result, server_name=server_name)
                    return result
            return wrapper
        return decorator

    # -- internals --------------------------------------------------------

    def _ids(self, session_id, transaction_id):
        rt_request, rt_session = _runtime_ids()
        return (transaction_id or rt_request or str(uuid.uuid4()),
                session_id or rt_session)

    def _text_leg(self, leg, contents, session_id, transaction_id):
        transaction_id, session_id = self._ids(session_id, transaction_id)
        # Each leg is judged on ITS OWN field: a prompt carried as context must
        # not satisfy the response leg's check, or a model turn with no text
        # would be recorded as a response that was scanned and allowed.
        text = contents.get("response") if leg == "response" else contents.get("prompt")
        if not isinstance(text, str) or not text.strip():
            self._log(leg, "unscannable", transaction_id, 0.0)
            if self.on_unscannable == "block":
                verdict = {"action": "block", "reason": "unscannable"}
                raise AIGuardBlocked(leg, verdict, transaction_id)
            return None
        return self._run(leg, [contents], session_id, transaction_id)

    def _tool_leg(self, leg, tool_name, tool_input, tool_output,
                  server_name, session_id, transaction_id):
        transaction_id, session_id = self._ids(session_id, transaction_id)
        tool_event = {
            "metadata": {
                "ecosystem": TOOL_ECOSYSTEM,   # only "mcp" is accepted by the service
                "method": "tools/call",
                "server_name": server_name,
                "tool_invoked": tool_name,
            },
            # Kept as a native object, not a pre-serialized string. The upstream
            # wire format required a JSON string here; serializing it twice leaves
            # escape noise ({\"ticket_id\": ...}) in the text the detectors read,
            # which measurably changes verdicts on otherwise identical content.
            "input": tool_input if tool_input is not None else {},
        }
        if tool_output is not None:
            tool_event["output"] = tool_output
        return self._run(leg, [{"tool_event": tool_event}], session_id, transaction_id,
                        tool_name=tool_name)

    def _unscannable_tool_output(self, tool_name, result):
        """A tool that handed back a coroutine or a lazy iterator produced
        nothing to scan yet -- it was a callable `inspect` could not classify at
        decoration time. That is unscannable output, not clean output, so it
        follows the on_unscannable posture instead of being scanned as a repr."""
        transaction_id, _ = self._ids(None, None)
        self._log("tool_output", "unscannable", transaction_id, 0.0, tool_name=tool_name)
        if self.on_unscannable == "block":
            # The value is being discarded here, so close what can be closed
            # rather than leave a bare "was never awaited" warning behind it.
            if inspect.iscoroutine(result) or inspect.isgenerator(result):
                result.close()
            raise AIGuardBlocked("tool_output",
                                    {"action": "block", "reason": "unscannable"},
                                    transaction_id, detail={"tool_name": tool_name})
        return result

    def _run(self, leg, contents, session_id, transaction_id, tool_name=None):
        api_key = os.environ.get("AIGUARD_API_KEY")
        endpoint = _default_endpoint()
        if not api_key:
            reason = "AIGUARD_API_KEY not set"
            self._log(leg, "error", transaction_id, 0.0, error=reason, tool_name=tool_name)
            if self.on_error == "block":
                raise AIGuardBlocked(leg, {"action": "block", "reason": "scan_error",
                                              "error": reason}, transaction_id)
            return None
        text, direction = _leg_payload(leg, contents)
        if not text.strip():
            self._log(leg, "unscannable", transaction_id, 0.0, tool_name=tool_name)
            if self.on_unscannable == "block":
                raise AIGuardBlocked(leg, {"action": "block", "reason": "unscannable"},
                                     transaction_id)
            return None
        payload = {"content": text, "direction": direction}
        api_transaction_id = _as_transaction_id(transaction_id or session_id)
        if api_transaction_id:
            payload["transactionId"] = api_transaction_id
        if self.policy_id is not None:
            payload["policyId"] = self.policy_id
        started = time.monotonic()
        verdict, error = _scan(endpoint, api_key, payload, self.timeout, self.policy_id)
        elapsed = (time.monotonic() - started) * 1000.0
        if error is None and not verdict.get("action"):
            error = ("scan response carries no action verdict"
                     + (" (statusCode=%s %s)" % (verdict.get("status_code"),
                                                 verdict.get("error_msg"))
                        if verdict.get("error_msg") or verdict.get("status_code") else ""))
        if error is None:
            action = str(verdict["action"]).lower()
            if action not in ("allow", "block"):
                error = "unknown scan action %r" % action
        if error is None and self.strict_verdict and action == "allow" and verdict.get("error_msg"):
            error = "degraded scan under strict_verdict (errorMsg=%s)" % verdict.get("error_msg")
        if error is not None:
            self._log(leg, "error", transaction_id, elapsed, error=error, tool_name=tool_name)
            if self.on_error == "block":
                raise AIGuardBlocked(leg, {"action": "block", "reason": "scan_error",
                                              "error": error}, transaction_id)
            return None
        self._log(leg, action, transaction_id, elapsed, verdict=verdict, tool_name=tool_name)
        if self.on_verdict is not None:
            try:
                self.on_verdict(leg, verdict)
            except Exception as exc:
                logger.warning("aiguard %s", json.dumps(
                    {"warning": "on_verdict callback failed", "error": str(exc)}))
        if action == "block":
            raise AIGuardBlocked(leg, verdict, transaction_id,
                                    detail={"tool_name": tool_name} if tool_name else None)
        return verdict

    def _identity(self):
        """Caller/agent identity for the log record.

        AI Guard's detection API carries no metadata field -- it takes content,
        direction, transactionId and policyId only -- so this identity cannot ride
        along with the scan. Emitting it on the local log line is what keeps a
        CloudWatch entry joinable to the agent that produced it; use the scan's
        transaction id to reach the matching record in the AI Guard console.
        """
        fields = {}
        if self.app_name:
            fields["app_name"] = self.app_name
        if self.app_user:
            fields["app_user"] = self.app_user
        if self.ai_model:
            fields["ai_model"] = self.ai_model
        if self.agent_meta:
            fields.update(self.agent_meta)
        return fields

    def _log(self, leg, action, transaction_id, elapsed_ms, verdict=None, error=None,
             tool_name=None):
        record = {"leg": leg, "action": action, "transaction_id": transaction_id,
                  "ms": round(elapsed_ms, 1)}
        record.update(self._identity())
        if tool_name:
            record["tool"] = tool_name
        if isinstance(verdict, dict):
            record["severity"] = verdict.get("severity")
            record["policy_name"] = verdict.get("policy_name")
            # The API assigns its own transaction id; keep it beside ours so a log
            # line can be matched to the scan record in the console.
            if verdict.get("transaction_id"):
                record["scan_transaction_id"] = verdict["transaction_id"]
            for key in ("triggered_detectors", "blocking_detectors"):
                if verdict.get(key):
                    record[key] = verdict[key]
            # A degraded-but-HTTP-200 verdict can carry the wrong type in any
            # of these fields, and summarising one for a log line must never
            # break a scan decision: every read is type-guarded, and the block
            # is wrapped, so a malformed verdict cannot raise past the caller's
            # except AIGuardBlocked.
            try:
                detected = {}
                for side in ("prompt_detected", "response_detected"):
                    side_map = verdict.get(side)
                    if not isinstance(side_map, dict):
                        continue
                    hits = [k for k, v in side_map.items() if v]
                    if hits:
                        detected[side] = hits
                td = verdict.get("tool_detected")
                if isinstance(td, dict):
                    summary = td.get("summary")
                    threats = summary.get("threats") if isinstance(summary, dict) else None
                    if threats:
                        detected["tool_threats"] = threats
                    if td.get("verdict"):
                        record["tool_verdict"] = td.get("verdict")
                if detected:
                    record["detected"] = detected
            except Exception as exc:
                record["summary_error"] = str(exc)
            if verdict.get("timeout"):
                record["timeout"] = True
            if verdict.get("error"):
                record["error_flag"] = True
        if error is not None:
            record["error"] = error
        line = "aiguard %s" % json.dumps(record, default=str)
        # Neutral outcomes read as INFO: an allow, and unscannable content when
        # the posture lets it through. A block or an error is a WARNING.
        neutral = action == "allow" or (action == "unscannable"
                                        and self.on_unscannable == "allow")
        (logger.info if neutral else logger.warning)(line)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _is_lazy(value):
    """True for a value that has produced nothing to scan yet -- a coroutine, an
    async generator or a generator. Scanning its repr would log an allow for
    output nobody inspected."""
    return (inspect.isawaitable(value) or inspect.isasyncgen(value)
            or inspect.isgenerator(value))


def _as_text(value):
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, default=str)


def _as_json(value):
    """tool_event input/output are raw JSON strings on the wire."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)

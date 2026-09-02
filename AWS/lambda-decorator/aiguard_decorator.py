"""
Zscaler AI Guard decorator for AWS Lambda handlers.

Wraps a Lambda handler so that:

  1. the inbound prompt is scanned by Zscaler AI Guard *before* the handler body runs
     (a blocked prompt never reaches the handler -- or any model behind it), and
  2. the handler's response is scanned *before* Lambda returns it to the caller
     (a blocked response is withheld).

Single file, standard library only. Copy it into your deployment package next
to your handler -- no layer, no requirements.txt, works on any python3.x
Lambda runtime and with any model provider the handler calls.

The decorator populates the full scan-request surface the platform can know:
transaction_id (the Lambda request id), session_id, and log identity (app_name / app_user /
ai_model / user_ip (auto-extracted from API Gateway events) / agent_meta, the
AI profile by name or id, and per-content code_prompt / code_response /
grounding context. On the verdict side it enforces `action`, surfaces
detection-service `timeout` / `error` / `errors`, can treat degraded scans as
failures (strict_verdict). `tool_event` is deliberately absent: nothing at the
function boundary can see tool calls -- that field belongs to the agent-loop
integrations.

Environment variables (standard Zscaler AI Guard names):

    AIGUARD_API_KEY        required   API key from the AI Guard Console
    AIGUARD_CLOUD          optional   cloud region, defaults to us1
    AIGUARD_POLICY_ID      optional   pin one policy; unset lets the API auto-resolve
    AIGUARD_TIMEOUT        optional   request timeout in seconds, defaults to 30
    AIGUARD_OVERRIDE_URL   optional   full base URL, overrides AIGUARD_CLOUD

Usage:

    from aiguard_decorator import aiguard_protect

    @aiguard_protect(app_name="support-chat")
    def handler(event, context):
        ...
"""

import base64
import functools
import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid

logger = logging.getLogger("aiguard")
if logger.level == logging.NOTSET:
    # Lambda's default (text) log config leaves the root level at WARNING;
    # without this, every INFO allow-line would be dropped before CloudWatch.
    logger.setLevel(logging.INFO)

DEFAULT_CLOUD = "us1"
RESOLVE_PATH = "/v1/detection/resolve-and-execute-policy"
EXECUTE_PATH = "/v1/detection/execute-policy"

# Request ids and caller-supplied session strings are not UUIDs, which the API
# requires for transactionId; hash them into this namespace deterministically.
_TRANSACTION_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "zscaler-aiguard/aws-lambda")

# Repo convention: app_name identifies the integration, and users append their
# own application name after it ("AWS-Lambda-support-chat").
APP_NAME_PREFIX = "AWS-Lambda"

# Keys the default extractors look for, in order, when the event / result is a
# JSON object. If your handler reads a different field, pass prompt_from= /
# response_from= so the scan sees exactly what the handler sees.
PROMPT_KEYS = ("prompt", "message", "input", "query", "question", "text")
RESPONSE_KEYS = ("response", "completion", "output", "answer", "reply", "message", "text")


class AIGuardBlocked(Exception):
    """Raised when a scan blocks an invocation that is not an HTTP proxy event.

    Raising -- rather than returning a block marker -- is what keeps the
    default safe on asynchronous event sources (SQS, SNS, EventBridge, S3,
    async invoke): Lambda engages retry, DLQ, and failure-destination
    semantics only when the invocation errors. A returned value would count
    as success and the event source would silently delete the messages.
    """

    def __init__(self, leg, verdict, transaction_id):
        self.leg = leg
        self.verdict = verdict
        self.transaction_id = transaction_id
        super().__init__(
            "blocked by Zscaler AI Guard on the %s leg (detectors=%s transaction_id=%s transaction_id=%s)"
            % (leg, (", ".join(verdict.get("blocking_detectors") or verdict.get("triggered_detectors") or []) or verdict.get("reason") or "policy"), verdict.get("transaction_id"), transaction_id)
        )


class _Skip:
    """Sentinel: this leg is intentionally not scanned (not an extraction failure)."""


_SKIP = _Skip()

# Public alias: return SKIP from a custom prompt_from/response_from to say
# "this invocation intentionally carries nothing to scan" (e.g. health checks)
# without tripping the fail-closed on_unscannable posture.
SKIP = _SKIP


# --------------------------------------------------------------------------
# default extractors
# --------------------------------------------------------------------------

def _is_http_event(event):
    """True for API Gateway (REST/HTTP/WebSocket), Function URL and ALB events.

    Recognized on the proxy envelope itself and not only on "body": an HTTP API
    (payload format 2.0) or Function URL event omits "body" entirely on a
    bodyless request -- a GET route, an OPTIONS preflight, an empty POST -- and
    those still have to receive the 403 rather than a raise the gateway renders
    as a generic 5xx. The final clause keeps every other envelope that carries a
    request context and a body, whose route marker sits somewhere this list does
    not name (an API Gateway WebSocket event puts routeKey inside
    requestContext).
    """
    if not isinstance(event, dict):
        return False
    ctx = event.get("requestContext")
    if not isinstance(ctx, dict):
        ctx = {}
    return bool(
        "httpMethod" in event                    # REST (v1) and ALB
        or "routeKey" in event                   # HTTP API (v2)
        or "http" in ctx                         # HTTP API (v2) / Function URL
        or "elb" in ctx                          # ALB target group
        or (event.get("version") == "2.0" and ctx)
        or ("body" in event and "requestContext" in event)  # any other proxy envelope
    )


def _decoded_body(envelope, raw):
    """A proxy envelope's body as text, base64-decoded when the envelope says so.

    Returns None when a flagged body is not valid base64 or does not decode to
    text (gzip, images, any binary media type): a blob is not scannable, so the
    leg must fail closed on the on_unscannable posture rather than scan -- or
    write a mask into -- the wrapper.
    """
    if not (isinstance(envelope, dict) and envelope.get("isBase64Encoded")):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        return base64.b64decode(raw).decode("utf-8")
    except Exception:
        return None



def _http_body(event):
    raw = event.get("body")
    if raw is None:
        return None
    return _decoded_body(event, raw)


def _first_text(obj, keys):
    if isinstance(obj, str):
        return obj if obj.strip() else None
    if isinstance(obj, dict):
        for key in keys:
            value = obj.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


def default_prompt_from(event):
    """Prompt text from an API Gateway/ALB proxy event or a direct-invoke payload."""
    if _is_http_event(event):
        raw = _http_body(event)
        if raw is None:
            return None
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            return raw if isinstance(raw, str) and raw.strip() else None
        return _first_text(parsed, PROMPT_KEYS)
    return _first_text(event, PROMPT_KEYS)


def default_response_from(result):
    """Response text from an API Gateway-shaped result or a plain return value."""
    if isinstance(result, dict) and "statusCode" in result:
        status = result.get("statusCode")
        if isinstance(status, int) and status >= 400:
            return _SKIP  # the handler's own error path carries no model output
        raw = result.get("body")
        if raw is None:
            return None
        raw = _decoded_body(result, raw)
        if raw is None:
            return None  # binary body: unscannable -- never scan the base64 wrapper
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            return raw if isinstance(raw, str) and raw.strip() else None
        return _first_text(parsed, RESPONSE_KEYS)
    return _first_text(result, RESPONSE_KEYS)


def default_user_ip_from(event, context=None):
    """End-user IP from API Gateway v1/v2 request context, else X-Forwarded-For."""
    if not isinstance(event, dict):
        return None
    ctx = event.get("requestContext") or {}
    ip = (ctx.get("http") or {}).get("sourceIp") or (ctx.get("identity") or {}).get("sourceIp")
    if ip:
        return ip
    headers = event.get("headers") or {}
    for name, value in headers.items():
        if isinstance(name, str) and name.lower() == "x-forwarded-for" and isinstance(value, str):
            return value.split(",")[0].strip() or None
    return None


# --------------------------------------------------------------------------
# the scan call
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would re-send the Bearer key to whatever host the 3xx names; refuse."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())

# A verdict is a few kilobytes; a body approaching this is a peer that will
# never finish. Same cap the other language integrations in this repo apply.
MAX_SCAN_RESPONSE_BYTES = 10 * 1024 * 1024
_READ_CHUNK = 65536


def _read_bounded(resp, deadline):
    """Read a scan response under a total deadline and a size cap.

    urlopen(timeout=) is a per-recv timeout: it restarts on every successful
    read, so a peer dribbling one byte at a time holds the handler far past
    `timeout` and the on_error posture is never reached. read1() returns what a
    single recv delivered, which is what lets the clock be checked in between.
    """
    read1 = getattr(resp, "read1", None)
    chunks = []
    total = 0
    while True:
        chunk = read1(_READ_CHUNK) if read1 is not None else resp.read(_READ_CHUNK)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_SCAN_RESPONSE_BYTES:
            raise ValueError("scan response exceeded %d bytes" % MAX_SCAN_RESPONSE_BYTES)
        chunks.append(chunk)
        if time.monotonic() >= deadline:
            raise TimeoutError("scan exceeded its time budget while reading the response")


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
    with an HTTP 500, and Lambda hands us aws_request_id. Hashing keeps the
    mapping deterministic, so an invocation stays correlatable in the console.
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


# Legs map onto AI Guard's two directions: IN is content heading into the model,
# OUT is what comes back out of it.
_LEG_DIRECTION = {"prompt": "IN", "response": "OUT"}


def _leg_payload(leg, contents):
    """Flatten a leg's content list into (text, direction) for the scan API."""
    direction = _LEG_DIRECTION.get(leg, "IN")
    parts = []
    for item in (contents or []):
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict):
            # "context" carries grounding text from context_from(); it is scanned
            # with the leg it accompanies, so a poisoned retrieval passage is seen.
            for key in ("prompt", "response", "code_prompt", "code_response", "context"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    parts.append(value)
    # Dedupe while preserving order: code_prompt often repeats prompt verbatim.
    seen, unique = set(), []
    for part in parts:
        if part not in seen:
            seen.add(part)
            unique.append(part)
    return ("\n".join(unique), direction)


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
    """POST one scan request. Returns (verdict_dict, None) or (None, error_str)."""
    if not endpoint.lower().startswith("https://"):
        return None, "refusing non-HTTPS endpoint: %s" % endpoint
    url = endpoint.rstrip("/") + (EXECUTE_PATH if policy_id is not None else RESOLVE_PATH)
    # One wall-clock budget for the whole call, not one per socket read.
    deadline = time.monotonic() + timeout
    try:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer %s" % api_key,
            },
            method="POST",
        )
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
    except Exception as exc:  # timeout, bad JSON, ...
        return None, "scan failed: %s" % exc


# --------------------------------------------------------------------------
# the decorator
# --------------------------------------------------------------------------

def aiguard_protect(
    app_name=None,
    policy_id=None,
    prompt_from=None,
    response_from=None,
    session_id_from=None,
    app_user_from=None,
    ai_model=None,
    user_ip_from=None,
    agent_meta=None,
    context_from=None,
    code_prompt_from=None,
    code_response_from=None,
    on_block=None,
    on_verdict=None,
    on_error="block",
    on_unscannable="block",
    strict_verdict=False,
    scan_prompt=True,
    scan_response=True,
    timeout=None,
):
    """
    Scan a Lambda handler's inbound prompt and outbound response with Zscaler AI Guard.

    Identity & profile
      app_name          appended to "AWS-Lambda-" in the log identity so a log line
                        logs identify both the integration and your application.
      policy_id         pin one policy id; omit to let the API auto-resolve
                        the policy bound to the API key (recommended).

    Extractors (all optional callables; return None when absent, SKIP to say
    "intentionally nothing to scan here")
      prompt_from(event)                -> str    text to scan before the handler
      response_from(result)             -> str    text to scan after the handler
      session_id_from(event, context)   -> str    conversation/session id (log correlation)
      app_user_from(event, context)     -> str    log identity: end user
      user_ip_from(event, context)      -> str    log identity: caller IP; defaults to the
                                                  API Gateway source IP / X-Forwarded-For
      context_from(event)               -> str    grounding context for the response leg
                                                  (feeds the "ungrounded" detection)
      code_prompt_from(event)           -> str    pre-extracted code from the prompt
      code_response_from(result)        -> str    pre-extracted code from the response

    Static log identity
      ai_model          string (or callable(event, context)) for log identity ai_model.
      agent_meta        dict with agent_id / agent_version / agent_arn. Off by
                        default: a plain Lambda is not an AI agent; the agent
                        integrations populate this themselves.

    Verdict handling
      on_block          callable(leg, verdict, event, context) -> replacement
                        return value. Default: HTTP 403 for proxy events,
                        raises AIGuardBlocked for everything else so async
                        event sources keep retry/DLQ semantics.
      on_verdict        callable(leg, verdict) observer, called for every scan
                        verdict (allow or block) -- metrics, audit, alerting.
      on_error          "block" (default) or "allow" when AI Guard is unreachable,
                        times out, errors, or credentials are missing.
      on_unscannable    "block" (default) or "allow" when no text can be
                        extracted. Fail-closed so a misconfigured extractor is
                        caught on the first test, not discovered as a bypass.
      strict_verdict    when True, a verdict that carries an `errorMsg` is
                        treated per on_error even if the action says "allow" --
                        a degraded scan is not proof of clean content.


    Toggles
      scan_prompt / scan_response       skip a leg entirely.
      timeout                           seconds per scan call (two per invocation).
                        Defaults to AIGUARD_TIMEOUT, else 30.
    """
    if on_error not in ("block", "allow"):
        raise ValueError('on_error must be "block" or "allow"')
    # None means "take AIGUARD_TIMEOUT", resolved once at decoration time.
    scan_timeout = _default_timeout() if timeout is None else timeout
    if on_unscannable not in ("block", "allow"):
        raise ValueError('on_unscannable must be "block" or "allow"')

    extract_prompt = prompt_from or default_prompt_from
    extract_response = response_from or default_response_from
    extract_user_ip = user_ip_from or default_user_ip_from
    full_app_name = "%s-%s" % (APP_NAME_PREFIX, app_name) if app_name else APP_NAME_PREFIX

    def _maybe(fn, *args):
        if fn is None:
            return None
        try:
            value = fn(*args)
        except Exception as exc:
            logger.warning("aiguard %s", json.dumps(
                {"warning": "metadata extractor %s failed" % getattr(fn, "__name__", "?"),
                 "error": str(exc)}))
            return None
        return value if isinstance(value, str) and value.strip() else None

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(event, context=None):
            api_key = os.environ.get("AIGUARD_API_KEY")
            endpoint = _default_endpoint()
            resolved_policy_id = _resolve_policy_id(policy_id)

            # transaction_id: the platform's own unique id for this invocation, so a
            # scan in the AI Guard console matches a request in CloudWatch.
            transaction_id = getattr(context, "aws_request_id", None) or str(uuid.uuid4())
            session_id = _maybe(session_id_from, event, context)

            # Caller identity for the log line only. AI Guard's detection API
            # carries no metadata field -- content, direction, transactionId and
            # policyId only -- so this cannot ride along with the scan. Emitting
            # it here keeps a CloudWatch entry joinable to the invocation that
            # produced it; the scan's own transaction id reaches the console.
            identity = {"app_name": full_app_name}
            app_user = _maybe(app_user_from, event, context)
            if app_user:
                identity["app_user"] = app_user
            model = _maybe(ai_model, event, context) if callable(ai_model) else ai_model
            if isinstance(model, str) and model.strip():
                identity["ai_model"] = model
            user_ip = _maybe(extract_user_ip, event, context)
            if user_ip:
                identity["user_ip"] = user_ip
            if isinstance(agent_meta, dict) and agent_meta:
                identity.update(agent_meta)

            def blocked(leg, verdict):
                if on_block is not None:
                    return on_block(leg, verdict, event, context)
                return _default_block_response(event, leg, verdict, transaction_id)

            leg_verdicts = {}

            def run_leg(leg, contents):
                """Returns None to continue, or a verdict dict that must block."""
                if not api_key:
                    reason = "AIGUARD_API_KEY not set"
                    _log_leg(leg, "error", transaction_id, 0.0, error=reason)
                    return {"action": "block", "reason": "scan_error", "error": reason} if on_error == "block" else None
                text, direction = _leg_payload(leg, [contents])
                if not text.strip():
                    _log_leg(leg, "unscannable", transaction_id, 0.0)
                    return {"action": "block", "reason": "unscannable"} \
                        if on_unscannable == "block" else None
                payload = {"content": text, "direction": direction}
                api_transaction_id = _as_transaction_id(transaction_id or session_id)
                if api_transaction_id:
                    payload["transactionId"] = api_transaction_id
                if resolved_policy_id is not None:
                    payload["policyId"] = resolved_policy_id
                started = time.monotonic()
                verdict, error = _scan(endpoint, api_key, payload, scan_timeout, resolved_policy_id)
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
                if error is None and strict_verdict and action == "allow" and verdict.get("error_msg"):
                    error = "degraded scan under strict_verdict (errorMsg=%s)" % verdict.get("error_msg")
                if error is not None:
                    _log_leg(leg, "error", transaction_id, elapsed, verdict=verdict, error=error)
                    return {"action": "block", "reason": "scan_error", "error": error} if on_error == "block" else None
                # Only an explicit "allow" passes. A confused endpoint that
                # answers 200 without a real verdict must not fail open.
                leg_verdicts[leg] = verdict
                _log_leg(leg, action, transaction_id, elapsed, verdict=verdict,
                         session_id=session_id, identity=identity)
                if on_verdict is not None:
                    try:
                        on_verdict(leg, verdict)
                    except Exception as exc:
                        logger.warning("aiguard %s", json.dumps(
                            {"warning": "on_verdict callback failed", "error": str(exc)}))
                return verdict if action == "block" else None

            # ---- leg 1: the prompt, before the handler runs -------------
            prompt_text = None
            if scan_prompt:
                extracted = None
                try:
                    extracted = extract_prompt(event)
                except Exception as exc:
                    _log_leg("prompt", "extract-error", transaction_id, 0.0, error=str(exc))
                if isinstance(extracted, _Skip):
                    _log_leg("prompt", "skipped", transaction_id, 0.0)
                elif not isinstance(extracted, str) or not extracted.strip():
                    _log_leg("prompt", "unscannable", transaction_id, 0.0,
                             neutral=(on_unscannable == "allow"))
                    if on_unscannable == "block":
                        return blocked("prompt", {"action": "block", "reason": "unscannable"})
                else:
                    prompt_text = extracted
                    contents = {"prompt": prompt_text}
                    code_prompt = _maybe(code_prompt_from, event)
                    if code_prompt:
                        contents["code_prompt"] = code_prompt
                    verdict = run_leg("prompt", contents)
                    if verdict is not None:
                        return blocked("prompt", verdict)

            # ---- the handler itself -------------------------------------
            result = fn(event, context)

            # ---- leg 2: the response, before it leaves ------------------
            if scan_response:
                response_text = None
                try:
                    response_text = extract_response(result)
                except Exception as exc:
                    _log_leg("response", "extract-error", transaction_id, 0.0, error=str(exc))
                if isinstance(response_text, _Skip):
                    _log_leg("response", "skipped", transaction_id, 0.0)
                elif not isinstance(response_text, str) or not response_text.strip():
                    _log_leg("response", "unscannable", transaction_id, 0.0,
                             neutral=(on_unscannable == "allow"))
                    if on_unscannable == "block":
                        return blocked("response", {"action": "block", "reason": "unscannable"})
                else:
                    # Send the prompt alongside the response: AI Guard detections
                    # that need conversational context see both sides.
                    contents = {"response": response_text}
                    if prompt_text:
                        contents["prompt"] = prompt_text
                    grounding = _maybe(context_from, event)
                    if grounding:
                        contents["context"] = grounding
                    code_response = _maybe(code_response_from, result)
                    if code_response:
                        contents["code_response"] = code_response
                    verdict = run_leg("response", contents)
                    if verdict is not None:
                        return blocked("response", verdict)

            return result

        return wrapper

    return decorator


# --------------------------------------------------------------------------
# block response, masking writer, logging
# --------------------------------------------------------------------------

def _default_block_response(event, leg, verdict, transaction_id):
    if _is_http_event(event):
        return {
            "statusCode": 403,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "blocked": True,
                "leg": leg,
                "severity": verdict.get("severity"),
                "policyName": verdict.get("policy_name"),
                "detectors": verdict.get("blocking_detectors")
                or verdict.get("triggered_detectors") or [],
                # Set only for verdicts this decorator synthesized (scan_error,
                # unscannable); a real policy block carries detectors instead.
                "reason": verdict.get("reason"),
                "transaction_id": verdict.get("transaction_id") or transaction_id,
                "message": "Request blocked by Zscaler AI Guard (%s scan)." % leg,
            }),
        }
    # Non-HTTP events (direct invoke, SQS, SNS, EventBridge, ...): raise, so
    # async event sources get retry/DLQ semantics instead of a silent success.
    # Pass on_block= to return a value instead if your sync caller prefers one.
    raise AIGuardBlocked(leg, verdict, transaction_id)



_NEUTRAL_ACTIONS = ("allow", "skipped")


def _log_leg(leg, action, transaction_id, elapsed_ms, verdict=None, error=None, session_id=None,
             neutral=False, identity=None):
    record = {"leg": leg, "action": action, "transaction_id": transaction_id, "ms": round(elapsed_ms, 1)}
    if identity:
        record.update(identity)
    if session_id:
        record["session_id"] = session_id
    if isinstance(verdict, dict):
        record["severity"] = verdict.get("severity")
        record["policy_name"] = verdict.get("policy_name")
        for key in ("triggered_detectors", "blocking_detectors"):
            if verdict.get(key):
                record[key] = verdict[key]
        if verdict.get("transaction_id"):
            record["scan_transaction_id"] = verdict["transaction_id"]
        detected = {}
        for side in ("prompt_detected", "response_detected"):
            # A verdict field of an unexpected type is loggable but unreadable:
            # logging must never break a scan decision the caller already made.
            side_hits = verdict.get(side)
            hits = [k for k, v in side_hits.items() if v] if isinstance(side_hits, dict) else []
            if hits:
                detected[side] = hits
        if detected:
            record["detected"] = detected
        details = {}
        for side in ("prompt_detection_details", "response_detection_details"):
            d = verdict.get(side)
            if not isinstance(d, dict):
                continue
            tgd = d.get("topic_guardrails_details")
            tg = tgd.get("blocked_topics") if isinstance(tgd, dict) else None
            toxd = d.get("toxic_content_details")
            tox = toxd.get("toxic_categories") if isinstance(toxd, dict) else None
            if tg:
                details.setdefault(side, {})["blocked_topics"] = tg
            if tox:
                details.setdefault(side, {})["toxic_categories"] = tox
        if details:
            record["details"] = details
        if verdict.get("error_msg"):
            record["error_msg"] = verdict["error_msg"]
    if error is not None:
        record["error"] = error
    line = "aiguard %s" % json.dumps(record)
    if neutral or action in _NEUTRAL_ACTIONS:
        logger.info(line)
    else:
        logger.warning(line)

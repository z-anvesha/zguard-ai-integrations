"""
Zscaler AI Guard scan hook for the Amazon Bedrock boto3 client.

Registers on the botocore event system so that EVERY Bedrock model invocation
made through a protected client -- including calls a framework makes on the
application's behalf -- is scanned by Zscaler AI Guard:

  * before-call   the outbound prompt is scanned; a blocked prompt never
                  leaves the process (the request is not signed, not sent,
                  and never billed -- botocore's request machinery is skipped)
  * after-call    the model's response is scanned before the application
                  sees it; a blocked response is withheld

A Bedrock guardrail is a request parameter: every call site must remember to
pass it, and a call without it is silently unguarded. A botocore handler is
registered on the client itself and applies to every call made through it.

Single file, depends only on the standard library plus botocore (which boto3
always brings). Works with Converse, ConverseStream, InvokeModel, and
InvokeModelWithResponseStream.

Environment variables (standard Zscaler AI Guard names):

    AIGUARD_API_KEY        required   API key from the AI Guard Console
    AIGUARD_CLOUD          optional   cloud region, defaults to us1
    AIGUARD_POLICY_ID      optional   pin one policy; unset lets the API auto-resolve
    AIGUARD_TIMEOUT        optional   request timeout in seconds, defaults to 30
    AIGUARD_OVERRIDE_URL   optional   full base URL, overrides AIGUARD_CLOUD

Usage:

    import boto3
    from aiguard_boto3_hook import protect_client

    bedrock = boto3.client("bedrock-runtime")
    protect_client(bedrock, app_name="support-chat")

    bedrock.converse(...)   # scanned, both directions
"""

import io
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from botocore.response import StreamingBody

logger = logging.getLogger("aiguard")

# Bedrock request ids and caller-supplied session strings are not UUIDs, which the
# API requires for transactionId; hash them into this namespace deterministically.
_TRANSACTION_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "zscaler-aiguard/aws-bedrock")
if logger.level == logging.NOTSET:
    logger.setLevel(logging.INFO)

DEFAULT_CLOUD = "us1"
RESOLVE_PATH = "/v1/detection/resolve-and-execute-policy"
EXECUTE_PATH = "/v1/detection/execute-policy"


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

# Repo convention: app_name identifies the integration, and users append their
# own application name after it ("AWS-Bedrock-support-chat").
APP_NAME_PREFIX = "AWS-Bedrock"

_HOOK_OPERATIONS = ("Converse", "ConverseStream", "InvokeModel", "InvokeModelWithResponseStream")
_STREAM_OPERATIONS = ("ConverseStream", "InvokeModelWithResponseStream")


class AIGuardBlocked(Exception):
    """Raised to the caller when a scan verdict blocks a model call."""

    def __init__(self, leg, verdict, transaction_id, operation=None):
        self.leg = leg
        self.verdict = verdict
        self.transaction_id = transaction_id
        self.operation = operation
        super().__init__(
            "blocked by Zscaler AI Guard on the %s leg of %s "
            "(severity=%s detectors=%s transaction_id=%s)"
            % (leg, operation or "a Bedrock call", verdict.get("severity"),
               ", ".join(verdict.get("blocking_detectors")
                         or verdict.get("triggered_detectors") or [])
               or verdict.get("reason") or "policy",
               verdict.get("transaction_id") or transaction_id)
        )


# --------------------------------------------------------------------------
# prompt / response extraction per Bedrock operation
# --------------------------------------------------------------------------

def _texts_from_converse_content(content):
    """(texts, opaque): every scannable string in a content-block list, and
    whether any block carries payloads that cannot be inspected as text.

    An allowlist with a fail-closed default. Two dialects share this walker:
    Converse discriminates its blocks by key ({"toolUse": ...}) while the
    messages dialect several InvokeModel model families speak tags them
    instead ({"type": "tool_use", ...}). Anything not recognized -- a binary
    payload, a malformed block, a content type Bedrock adds after this file
    was written -- sets `opaque`, so the on_unscannable posture governs it
    rather than it silently vanishing from the scan.
    """
    if isinstance(content, str):
        return ([content] if content.strip() else []), False
    texts, opaque = [], False
    for block in content or []:
        if isinstance(block, dict):
            found, unreadable = (_texts_from_tagged_block(block)
                                 if isinstance(block.get("type"), str)
                                 else _texts_from_converse_block(block))
        else:
            found, unreadable = [], True
        texts += found
        opaque = opaque or unreadable
    return texts, opaque


def _texts_from_converse_block(block):
    """(texts, opaque) for one Converse content block, keyed by member name."""
    if isinstance(block.get("text"), str):
        return [block["text"]], False
    if "guardContent" in block:
        guard = block.get("guardContent")
        guard = guard if isinstance(guard, dict) else {}
        nested = guard.get("text")
        text = nested.get("text") if isinstance(nested, dict) else None
        # guardContent can also carry an image; that half is not inspectable.
        others = [key for key in guard if key != "text"]
        if isinstance(text, str):
            return [text], bool(others)
        return [], True
    if "toolUse" in block:
        return _texts_from_tool_call(block.get("toolUse"))
    if "toolResult" in block:
        result = block.get("toolResult")
        if not isinstance(result, dict):
            return [], True
        return _texts_from_tool_result(result.get("content"))
    if "reasoningContent" in block:
        reasoning = block.get("reasoningContent")
        reasoning = reasoning if isinstance(reasoning, dict) else {}
        nested = reasoning.get("reasoningText")
        text = nested.get("text") if isinstance(nested, dict) else None
        if isinstance(text, str):
            return [text], False
        return [], True                 # redactedContent is an encrypted blob
    if "searchResult" in block:
        return _texts_from_search_result(block.get("searchResult"))
    if "citationsContent" in block:
        return _texts_from_citations(block.get("citationsContent"))
    if "cachePoint" in block:
        # A prompt-caching marker, not content: its only members are type and
        # ttl and it delivers nothing to the model, so it is neither scannable
        # nor opaque. Any other member is content riding behind the marker.
        marker = block.get("cachePoint")
        members = list(marker) if isinstance(marker, dict) else []
        if members and all(key in ("type", "ttl") for key in members):
            return [], False
        return [], True
    # document / image / video / audio -- and, fail-closed, everything else.
    return [], True


def _texts_from_tagged_block(block):
    """(texts, opaque) for one messages-dialect block, keyed by its `type` tag.
    Both legs speak this dialect: a model-emitted tool call carries arguments
    the application is about to act on."""
    kind = block.get("type")
    if kind == "text":
        text = block.get("text")
        return ([text], False) if isinstance(text, str) else ([], True)
    if kind == "tool_use":
        return _texts_from_tool_call(block)
    if kind == "tool_result":
        return _texts_from_converse_content(block.get("content"))
    if kind == "thinking":
        text = block.get("thinking")
        return ([text], False) if isinstance(text, str) else ([], True)
    # redacted_thinking / image / document -- and, fail-closed, everything else.
    return [], True


def _texts_from_tool_call(tool):
    """A tool call in either dialect: the tool name plus its serialized
    arguments, which the model wrote and the application is about to run."""
    if not isinstance(tool, dict):
        return [], True
    texts = []
    name = tool.get("name")
    if isinstance(name, str) and name.strip():
        texts.append(name)
    if "input" in tool:
        texts.append(_json_text(tool.get("input")))
    return (texts, False) if texts else ([], True)


def _texts_from_tool_result(content):
    """The members of a tool result. Tool output is attacker-reachable text --
    the classic indirect-injection carrier -- so it is walked, not skipped."""
    if isinstance(content, str):
        return ([content] if content.strip() else []), False
    texts, opaque = [], False
    for sub in content or []:
        if not isinstance(sub, dict):
            opaque = True
        elif isinstance(sub.get("text"), str):
            texts.append(sub["text"])
        elif "json" in sub:
            texts.append(_json_text(sub["json"]))
        elif "searchResult" in sub:
            found, unreadable = _texts_from_search_result(sub.get("searchResult"))
            texts += found
            opaque = opaque or unreadable
        else:                          # document / image / video, and the rest
            opaque = True
    return texts, opaque


def _texts_from_search_result(result):
    """Retrieved passages, whether they arrive top level or inside a tool
    result -- retrieved text is the payload an indirect injection rides in."""
    if not isinstance(result, dict):
        return [], True
    texts, opaque = [], False
    for sub in result.get("content") or []:
        if isinstance(sub, dict) and isinstance(sub.get("text"), str):
            texts.append(sub["text"])
        else:
            opaque = True
    return texts, opaque


def _texts_from_citations(citations):
    """A citations block carries the model's own generated answer plus the
    source passages it cites -- both are text the caller will render."""
    if not isinstance(citations, dict):
        return [], True
    texts, opaque = [], False
    for sub in citations.get("content") or []:
        if isinstance(sub, dict) and isinstance(sub.get("text"), str):
            texts.append(sub["text"])
        else:
            opaque = True
    for citation in citations.get("citations") or []:
        if not isinstance(citation, dict):
            opaque = True
            continue
        for sub in citation.get("sourceContent") or []:
            if isinstance(sub, dict) and isinstance(sub.get("text"), str):
                texts.append(sub["text"])
            else:
                opaque = True
    return texts, opaque


def _json_text(value):
    """Serialize a JSON-ish payload for scanning. Extraction runs inside the
    caller's SDK call, so this never raises: a value that will not serialize is
    scanned as its string form instead of crashing the request."""
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _prompt_from_converse_body(body):
    """(text, opaque): the system prompt plus EVERY user-role message, not just
    the newest one -- a single call can smuggle instructions in any of them.
    Assistant-role turns and tool specifications are not scanned here."""
    texts, opaque = [], False
    system = body.get("system")
    if isinstance(system, str):
        if system.strip():
            texts.append(system)
    elif isinstance(system, list):
        found, unreadable = _texts_from_converse_content(system)
        texts += found
        opaque = opaque or unreadable
    elif system is not None:
        opaque = True                  # a system field we cannot read
    for message in body.get("messages") or []:
        if not isinstance(message, dict):
            # A message shape we cannot read is a message we cannot scan.
            opaque = True
            continue
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            texts.append(content)
        else:
            found, unreadable = _texts_from_converse_content(content)
            texts += found
            opaque = opaque or unreadable
    return ("\n".join(texts) if texts else None), opaque


# Model families speak different body dialects through InvokeModel. Known
# families get precise extraction; anything unknown falls back to scanning the
# entire serialized body, which errs toward inspecting too much rather than
# too little.
def _prompt_from_invoke_body(body):
    """(text, opaque) for the InvokeModel dialects."""
    if isinstance(body.get("messages"), list):        # messages dialect (incl. amazon nova)
        prompt, opaque = _prompt_from_converse_body(body)
        if prompt or opaque:
            return prompt, opaque
    if isinstance(body.get("message"), str):          # cohere
        texts = []
        for turn in body.get("chat_history") or []:   # every turn, not just the newest
            if isinstance(turn, dict) and isinstance(turn.get("message"), str):
                texts.append(turn["message"])
        if body["message"].strip():
            texts.append(body["message"])
        # Grounding documents and tool results are model-visible text too, and
        # are exactly where a retrieved injection rides.
        for key in ("documents", "tool_results"):
            items = body.get(key)
            if isinstance(items, list) and items:
                texts.append(_json_text(items))
        if texts:
            return "\n".join(texts), False
    for key in ("inputText", "prompt"):               # titan / llama, mistral
        if isinstance(body.get(key), str) and body[key].strip():
            return body[key], False
    return None, False


def _converse_message(parsed):
    """The assistant message of a parsed Converse response, or None."""
    output = parsed.get("output")
    message = output.get("message") if isinstance(output, dict) else None
    return message if isinstance(message, dict) else None


def _response_from_converse_parsed(parsed):
    message = _converse_message(parsed)
    texts, _ = _texts_from_converse_content(message.get("content") if message else None)
    return "\n".join(texts) if texts else None


def _response_from_invoke_body(body):
    if isinstance(body.get("content"), list):         # messages-dialect content list
        texts, _ = _texts_from_converse_content(body["content"])
        if texts:
            return "\n".join(texts)
    output = body.get("output")
    if isinstance(output, dict):                      # nova
        message = output.get("message")
        texts, _ = _texts_from_converse_content(
            message.get("content") if isinstance(message, dict) else None)
        if texts:
            return "\n".join(texts)
    results = body.get("results")
    if isinstance(results, list) and results and isinstance(results[0], dict):   # titan
        text = results[0].get("outputText")
        if isinstance(text, str) and text.strip():
            return text
    for key in ("generation", "outputs", "text", "completion"):  # llama / mistral / cohere
        value = body.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, list) and value and isinstance(value[0], dict):
            text = value[0].get("text")
            if isinstance(text, str) and text.strip():
                return text
    return None


def _model_id_from_request(params):
    # The serialized url_path is /model/{modelId}/converse etc.
    path = params.get("url_path") or ""
    parts = path.split("/")
    if "model" in parts:
        candidate = parts[parts.index("model") + 1] if parts.index("model") + 1 < len(parts) else ""
        return urllib.parse.unquote(candidate) or None
    return None


def _request_body_json(params):
    raw = params.get("body")
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str) or not raw.strip():
        return None, None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None, raw
    return (parsed, raw) if isinstance(parsed, dict) else (None, raw)


# --------------------------------------------------------------------------
# the scan call (same hardened client as the other AWS integrations)
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would re-send the Bearer key to whatever host the 3xx names; refuse."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())

# A scan verdict is a few kilobytes; anything beyond this is a peer that is not
# the AI Guard API, and reading it would spend the caller's latency budget.
_MAX_SCAN_RESPONSE_BYTES = 10 * 1024 * 1024


def _read_bounded(resp, deadline):
    """Read a response body under a wall-clock deadline and a size cap.

    `timeout=` on urlopen is a per-recv timeout: it resets on every successful
    read, so a peer that trickles the body holds the caller far past it and the
    on_error posture never gets to run. Taking one recv at a time and checking
    the clock between them bounds the whole read to the configured timeout plus
    at most one recv.
    """
    read_once = getattr(resp, "read1", None) or resp.read
    chunks, total = [], 0
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("timed out reading the scan response")
        chunk = read_once(65536)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > _MAX_SCAN_RESPONSE_BYTES:
            raise ValueError("scan response exceeded %d bytes" % _MAX_SCAN_RESPONSE_BYTES)
        chunks.append(chunk)


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
    with an HTTP 500, and callers pass Bedrock request ids and session strings.
    Hashing keeps the mapping deterministic, so the same call always reports the
    same transaction id and stays correlatable in the console.
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


def _normalize_verdict(parsed):
    """Fold an AI Guard response into the verdict shape the hook legs consume.

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
            body = exc.read(_MAX_SCAN_RESPONSE_BYTES).decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        return None, "HTTP %s from AI Guard: %s" % (exc.code, body)
    except urllib.error.URLError as exc:
        return None, "network error reaching AI Guard: %s" % exc.reason
    except TimeoutError as exc:
        return None, "scan timed out after %ss: %s" % (timeout, exc)
    except Exception as exc:
        return None, "scan failed: %s" % exc


# --------------------------------------------------------------------------
# the hook
# --------------------------------------------------------------------------

def _register(events, hook):
    """Register both legs for every intercepted operation.

    The unique id makes the registration idempotent inside botocore itself: a
    client created from a protected session carries a copy of the session's
    registrations, so protecting that client as well adds nothing instead of
    scanning -- and billing, and logging -- every call twice.
    """
    for operation in _HOOK_OPERATIONS:
        events.register("before-call.bedrock-runtime.%s" % operation, hook.before_call,
                        unique_id="aiguard-before-%s" % operation)
        events.register("after-call.bedrock-runtime.%s" % operation, hook.after_call,
                        unique_id="aiguard-after-%s" % operation)


def protect_client(client, **config):
    """Register AI Guard scanning on one bedrock-runtime client. Returns the client.
    Protecting the same client twice is a no-op, not a double scan; so is
    protecting a client created from an already protected session, which keeps
    the session's configuration."""
    if getattr(client, "_aiguard_protected", False):
        return client
    # Build the hook first: an invalid option must raise before the client is
    # marked protected, or a corrected retry would find the marker and register
    # nothing at all.
    hook = _Hook(config)
    _register(client.meta.events, hook)
    client._aiguard_protected = True
    return client


def protect_session(session, **config):
    """Register AI Guard scanning on a boto3 Session: every bedrock-runtime client
    created from it afterwards is protected. Returns the session.
    Protecting the same session twice is a no-op, not a double scan."""
    if getattr(session, "_aiguard_protected", False):
        return session
    hook = _Hook(config)
    _register(session.events, hook)
    session._aiguard_protected = True
    return session


class _Hook:
    def __init__(self, config):
        valid = {"app_name", "policy_id", "session_id", "app_user",
                 "on_block", "on_verdict", "on_error", "on_unscannable",
                 "strict_verdict", "scan_prompt",
                 "scan_response", "timeout"}
        unknown = set(config) - valid
        if unknown:
            raise TypeError("unknown options: %s" % ", ".join(sorted(unknown)))
        self.app_name = config.get("app_name")
        self.policy_id = _resolve_policy_id(config.get("policy_id"))
        self.session_id = config.get("session_id")
        self.app_user = config.get("app_user")
        self.on_block = config.get("on_block", "raise")
        self.on_verdict = config.get("on_verdict")
        self.on_error = config.get("on_error", "block")
        self.on_unscannable = config.get("on_unscannable", "block")
        self.strict_verdict = config.get("strict_verdict", False)
        self.scan_prompt = config.get("scan_prompt", True)
        self.scan_response = config.get("scan_response", True)
        self.timeout = config.get("timeout", _default_timeout())
        if self.on_block not in ("raise", "respond"):
            raise ValueError('on_block must be "raise" or "respond"')
        if self.on_error not in ("block", "allow"):
            raise ValueError('on_error must be "block" or "allow"')
        if self.on_unscannable not in ("block", "allow"):
            raise ValueError('on_unscannable must be "block" or "allow"')

    # -- leg 1: before the request is signed or sent ----------------------
    def before_call(self, model, params, **kwargs):
        operation = model.name
        # Recorded before the scan_prompt gate: the response leg needs the model
        # id and the transaction id even where only egress is enforced.
        transaction_id = str(uuid.uuid4())
        context = kwargs.get("context")
        model_id = _model_id_from_request(params)
        if isinstance(context, dict):
            context["aiguard"] = {"transaction_id": transaction_id, "model_id": model_id}
        if not self.scan_prompt:
            return None
        prompt, opaque = self._extract_prompt(operation, params)
        if opaque and self.on_unscannable == "block":
            # Content that cannot be inspected as text rides in this request --
            # a document, an image, video, audio, or a block shape this hook
            # does not recognize -- so the fail-closed posture governs.
            self._log("prompt", "unscannable", transaction_id, 0.0, operation=operation,
                      note="content that cannot be inspected as text")
            return self._blocked("prompt", {"action": "block", "reason": "unscannable"},
                                 transaction_id, operation, model_id)
        if not isinstance(prompt, str) or not prompt.strip():
            self._log("prompt", "unscannable", transaction_id, 0.0, operation=operation)
            if self.on_unscannable == "block":
                return self._blocked("prompt", {"action": "block", "reason": "unscannable"},
                                     transaction_id, operation, model_id)
            return None
        blocked_verdict, _ = self._run_leg("prompt", {"prompt": prompt},
                                           transaction_id, operation, model_id)
        if blocked_verdict is not None:
            return self._blocked("prompt", blocked_verdict, transaction_id, operation, model_id)
        if isinstance(context, dict):
            context["aiguard"]["prompt"] = prompt
        return None  # fall through to botocore's normal request path

    # -- leg 2: after the response is parsed, before the caller sees it ---
    def after_call(self, http_response, parsed, model, **kwargs):
        operation = model.name
        if not self.scan_response or not isinstance(parsed, dict):
            return
        if ((parsed.get("ResponseMetadata") or {}).get("AIGuard") or {}).get("blocked"):
            # Our own synthetic short-circuit response: botocore emits
            # after-call even for short-circuited calls, and re-scanning our
            # block notice would waste a scan and could overwrite the verdict.
            return
        if "Error" in parsed or getattr(http_response, "status_code", 200) >= 300:
            # An AWS error response carries no model output; scanning or
            # blocking it would only mask the real exception botocore is
            # about to raise to the caller.
            return
        context = kwargs.get("context")
        state = (context or {}).get("aiguard", {}) if isinstance(context, dict) else {}
        transaction_id = state.get("transaction_id") or str(uuid.uuid4())
        if operation in _STREAM_OPERATIONS:
            # The body is an event stream still on the wire; there is nothing
            # complete to scan here. See the README's streaming section.
            self._log("response", "skipped-stream", transaction_id, 0.0, operation=operation)
            return
        raw_invoke = None
        if operation == "Converse":
            response_text = self._extract_response(operation, parsed, None)
        else:  # InvokeModel: parsed["body"] is a StreamingBody -- read and later restore
            try:
                stream = parsed.get("body")
                raw_invoke = stream.read() if hasattr(stream, "read") else stream
            except Exception as exc:
                _warn("could not read the response body", exc, operation)
            try:
                body = json.loads(raw_invoke.decode("utf-8", errors="replace")
                                  if isinstance(raw_invoke, (bytes, bytearray)) else raw_invoke)
            except (ValueError, AttributeError, TypeError):
                body = None
            response_text = self._extract_response(operation, parsed, body)
            if response_text is None and raw_invoke:
                response_text = raw_invoke.decode("utf-8", errors="replace") \
                    if isinstance(raw_invoke, (bytes, bytearray)) else str(raw_invoke)
        if not isinstance(response_text, str) or not response_text.strip():
            self._log("response", "unscannable", transaction_id, 0.0, operation=operation)
            if self.on_unscannable == "block":
                self._restore_invoke_body(parsed, raw_invoke)
                self._deliver_response_block(
                    parsed, {"action": "block", "reason": "unscannable"},
                    transaction_id, operation)
            else:
                self._restore_invoke_body(parsed, raw_invoke)
            return
        contents = {"response": response_text}
        prompt = state.get("prompt")
        if prompt:
            contents["prompt"] = prompt
        blocked_verdict, allow_verdict = self._run_leg("response", contents, transaction_id,
                                                        operation, state.get("model_id"))
        self._restore_invoke_body(parsed, raw_invoke)
        if blocked_verdict is not None:
            self._deliver_response_block(parsed, blocked_verdict, transaction_id, operation)
            return

    # -- shared plumbing ---------------------------------------------------
    def _extract_prompt(self, operation, params):
        """(text, opaque) for the request body. Extraction runs inside the
        caller's SDK call, so a body this hook cannot walk comes back opaque and
        follows the on_unscannable posture instead of raising out of converse()."""
        try:
            body, raw = _request_body_json(params)
            if body is None:
                return raw, False
            if operation.startswith("Converse"):
                return _prompt_from_converse_body(body)
            prompt, opaque = _prompt_from_invoke_body(body)
            if prompt is None and not opaque:
                prompt = raw           # unknown dialect: scan the whole body
            return prompt, opaque
        except Exception as exc:
            _warn("prompt extraction failed", exc, operation)
            return None, True

    def _extract_response(self, operation, parsed, body):
        """The response text to scan, or None. Same contract as _extract_prompt:
        a shape this hook cannot walk is unscannable, never an exception."""
        try:
            if operation == "Converse":
                return _response_from_converse_parsed(parsed)
            return _response_from_invoke_body(body) if isinstance(body, dict) else None
        except Exception as exc:
            _warn("response extraction failed", exc, operation)
            return None

    def _run_leg(self, leg, contents, transaction_id, operation, model_id):
        api_key = os.environ.get("AIGUARD_API_KEY")
        endpoint = _default_endpoint()
        if not api_key:
            reason = "AIGUARD_API_KEY not set"
            self._log(leg, "error", transaction_id, 0.0, error=reason, operation=operation)
            return ({"action": "block", "reason": "scan_error", "error": reason}, None) \
                if self.on_error == "block" else (None, None)

        # One leg is one direction: the prompt leg scans what is going to the
        # model, the response leg what is coming back.
        direction = "IN" if leg == "prompt" else "OUT"
        text = contents.get("prompt") if leg == "prompt" else contents.get("response")
        if not isinstance(text, str) or not text.strip():
            self._log(leg, "unscannable", transaction_id, 0.0, operation=operation)
            return ({"action": "block", "reason": "unscannable"}, None) \
                if self.on_unscannable == "block" else (None, None)

        payload = {"content": text, "direction": direction}
        api_transaction_id = _as_transaction_id(transaction_id)
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
                error = "unknown scan action %r" % verdict.get("raw_action", action)
        if error is None and self.strict_verdict and action == "allow" and verdict.get("error_msg"):
            error = "degraded scan under strict_verdict (errorMsg=%s)" % verdict.get("error_msg")
        if error is not None:
            self._log(leg, "error", transaction_id, elapsed, error=error, operation=operation)
            return ({"action": "block", "reason": "scan_error", "error": error}, None) \
                if self.on_error == "block" else (None, None)
        self._log(leg, action, transaction_id, elapsed, verdict=verdict, operation=operation)
        if self.on_verdict is not None:
            try:
                self.on_verdict(leg, verdict)
            except Exception as exc:
                logger.warning("aiguard %s", json.dumps(
                    {"warning": "on_verdict callback failed", "error": str(exc)}))
        return (verdict, None) if action == "block" else (None, verdict)

    def _blocked(self, leg, verdict, transaction_id, operation, model_id):
        """Return value for before-call: raising or a synthetic (http, parsed) pair."""
        if self.on_block == "raise":
            raise AIGuardBlocked(leg, verdict, transaction_id, operation)
        message = ("This request was blocked by Zscaler AI Guard (%s scan, severity=%s, "
                   "detectors=%s, transaction_id=%s)."
                   % (leg, verdict.get("severity"),
                      ", ".join(verdict.get("blocking_detectors")
                                or verdict.get("triggered_detectors") or [])
                      or verdict.get("reason") or "policy",
                      verdict.get("transaction_id") or transaction_id))
        meta = {"HTTPStatusCode": 200, "AIGuard": {
            "blocked": True, "leg": leg, "severity": verdict.get("severity"),
            "policyName": verdict.get("policy_name"),
            "detectors": verdict.get("blocking_detectors")
            or verdict.get("triggered_detectors") or [],
            "transaction_id": verdict.get("transaction_id") or transaction_id}}
        if operation == "ConverseStream":
            # A minimal, valid event stream: the standard consumer loop plays
            # it back exactly like a real streamed reply.
            parsed = {"ResponseMetadata": meta, "stream": iter([
                {"messageStart": {"role": "assistant"}},
                {"contentBlockDelta": {"delta": {"text": message}, "contentBlockIndex": 0}},
                {"contentBlockStop": {"contentBlockIndex": 0}},
                {"messageStop": {"stopReason": "content_filtered"}},
            ])}
        elif operation == "InvokeModelWithResponseStream":
            chunk = json.dumps({"aiguard_blocked": True, "message": message}).encode("utf-8")
            parsed = {"ResponseMetadata": meta, "contentType": "application/json",
                      "body": iter([{"chunk": {"bytes": chunk}}])}
        elif operation == "InvokeModel":
            body = json.dumps({"aiguard_blocked": True, "message": message}).encode("utf-8")
            parsed = {"ResponseMetadata": meta, "contentType": "application/json",
                      "body": _fresh_body(body)}
        else:
            parsed = {
                "ResponseMetadata": meta,
                "output": {"message": {"role": "assistant", "content": [{"text": message}]}},
                "stopReason": "content_filtered",
                "usage": {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0},
            }
        return _SyntheticHttp(), parsed

    def _deliver_response_block(self, parsed, verdict, transaction_id, operation):
        """after-call cannot short-circuit; it blocks by raising or by rewriting parsed."""
        if self.on_block == "raise":
            raise AIGuardBlocked("response", verdict, transaction_id, operation)
        message = ("The model response was withheld by Zscaler AI Guard (severity=%s, "
                   "detectors=%s, transaction_id=%s)."
                   % (verdict.get("severity"),
                      ", ".join(verdict.get("blocking_detectors")
                                or verdict.get("triggered_detectors") or [])
                      or verdict.get("reason") or "policy",
                      verdict.get("transaction_id") or transaction_id))
        replaced = self._replace_response_text(parsed, message, operation)
        if operation == "Converse":
            # The caller receives a filtered reply, so it must not still read
            # "tool_use": an agent loop branching on stopReason would go hunting
            # for a tool call that is no longer there.
            parsed["stopReason"] = "content_filtered"
        meta = parsed.setdefault("ResponseMetadata", {})
        meta["AIGuard"] = {"blocked": True, "leg": "response",
                              "severity": verdict.get("severity"),
                              "policyName": verdict.get("policy_name"),
                              "detectors": verdict.get("blocking_detectors")
                              or verdict.get("triggered_detectors") or [],
                              "transaction_id": transaction_id}
        if not replaced:
            # The response shape could not carry the notice; the block is still
            # recorded under ResponseMetadata, which is the documented channel.
            self._log("response", "block-unappliable", transaction_id, 0.0,
                      operation=operation, note="response shape carries no text to replace")

    def _replace_response_text(self, parsed, text, operation):
        """The block path replaces the response outright: the model's own output
        is withheld, and leaving a toolUse block behind would hand the caller a
        tool call that nothing cleared."""
        if operation == "Converse":
            message = _converse_message(parsed)
            if message is not None and isinstance(message.get("content"), list):
                message["content"] = [{"text": text}]
                return True
            # An output shape we do not recognize still must not reach the
            # caller carrying the text the verdict withheld.
            parsed["output"] = {"message": {"role": "assistant",
                                            "content": [{"text": text}]}}
            return True
        if "body" in parsed:
            parsed["body"] = _fresh_body(
                json.dumps({"aiguard": "response replaced", "text": text}).encode("utf-8"))
            return True
        return False

    @staticmethod
    def _restore_invoke_body(parsed, raw):
        """Put the InvokeModel body back after reading it for the response scan.

        Reading a StreamingBody consumes it, so the caller would otherwise get an
        empty body on every allowed InvokeModel call.
        """
        if raw is not None:
            parsed["body"] = _fresh_body(raw)

    @staticmethod
    def _log(leg, action, transaction_id, elapsed_ms, verdict=None, error=None,
             operation=None, note=None):
        record = {"leg": leg, "action": action, "transaction_id": transaction_id,
                  "ms": round(elapsed_ms, 1)}
        if note:
            record["note"] = note
        if operation:
            record["operation"] = operation
        if isinstance(verdict, dict):
            try:
                record["severity"] = verdict.get("severity")
                record["policy_name"] = verdict.get("policy_name")
                record["transaction_id"] = verdict.get("transaction_id") or record.get("transaction_id")
                for key in ("triggered_detectors", "blocking_detectors"):
                    if verdict.get(key):
                        record[key] = verdict[key]
                detected = {}
                for side in ("prompt_detected", "response_detected"):
                    flags = verdict.get(side)
                    hits = [k for k, v in flags.items() if v] if isinstance(flags, dict) else []
                    if hits:
                        detected[side] = hits
                if detected:
                    record["detected"] = detected
                if verdict.get("timeout"):
                    record["timeout"] = True
                if verdict.get("error"):
                    record["error_flag"] = True
            except Exception:
                # A verdict whose fields are not the documented shapes is still
                # loggable; summarising it must never break a scan decision.
                record["verdict"] = "unreadable"
        if error is not None:
            record["error"] = error
        line = "aiguard %s" % json.dumps(record, default=str)
        (logger.info if action in ("allow", "skipped-stream", "masked") else logger.warning)(line)


def _warn(what, exc, operation):
    """One warning line for a failure that degraded a leg but must not reach
    the caller as an exception."""
    logger.warning("aiguard %s", json.dumps(
        {"warning": what, "error": str(exc), "operation": operation}))


def _fresh_body(data):
    """A genuine botocore StreamingBody over in-memory bytes, so replaced
    InvokeModel bodies keep the full public API (iter_chunks, iter_lines, ...)."""
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8")
    return StreamingBody(io.BytesIO(data), len(data))


class _SyntheticHttp:
    """The http half of a short-circuited before-call response."""

    status_code = 200
    headers = {}
    content = b""

    def __init__(self):
        self.raw = None

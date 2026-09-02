# Architecture — Apigee X + Zscaler AI Guard SharedFlow

How the `ZSCALER-AIGUARD` SharedFlow works, and why it is shaped this way. For
setup and usage see [README.md](README.md).

## 1. Big picture

```
        request                                            response
           │                                                   │
   ┌───────▼────────┐                                 ┌────────▼───────┐
   │ FC-CallAIGuard │  type=user-prompt               │ FC-CallAIGuard │  type=response-prompt
   │     Input      │                                 │     Output     │
   └───────┬────────┘                                 └────────┬───────┘
           │                                                   │
           └──────────────► ZSCALER-AIGUARD ◄──────────────────┘
                            (one SharedFlow,
                             both directions)
                                    │
                          POST /v1/detection/
                       resolve-and-execute-policy
                                    │
                            ALLOW ──┴── BLOCK
                              │           │
                        continue to    RF-Block:
                          Vertex       native-shape
                                        refusal
```

The same flow runs on both legs. What differs is the `type` parameter on the
FlowCallout, which becomes `aiguard.cfg.phase`, which decides the scan
**direction**: `prompt → IN`, `response → OUT`.

## 2. Why a SharedFlow at all

The inline-policy proxy in [`../apiproxy`](../apiproxy) does the same scanning
with its policies baked in. That is simpler for one proxy and worse for several:
every new proxy copies the policies, and a fix has to be applied everywhere.

A SharedFlow is deployed once and called by any number of proxies with a
two-line FlowCallout. One bundle holds the extraction logic, the API contract and
the block shapes; proxies stay thin. The trade-off is one more deployable
artefact and an extra hop in the trace.

| | Inline proxy | SharedFlow |
|---|---|---|
| Bundles to deploy | 1 | 2 (flow + proxy) |
| Cost of a second proxy | copy all policies | 2 lines |
| Fixing the scan logic | edit every proxy | edit one bundle |
| Best for | a single LLM proxy | a shared posture |

## 3. The request lifecycle

`sharedflowbundle/sharedflows/default.xml` runs thirteen steps, each gated so the
flow is a clean no-op when there is nothing to scan.

| # | Step | Purpose |
|---|------|---------|
| 1 | `KVM-GetAIGuardConfig` | API key (and optional pinned policy id) from the encrypted KVM |
| 2 | `JS-InitConfig` | normalise every knob into `aiguard.cfg.*` |
| 3 | `RF-ConfigError` | fail-closed guard: no API key configured |
| 4 | `JS-DetectContext` | classify the dialect, decide whether to scan, derive ids |
| 5 | `JS-ExtractContent` | pull the text out of the caller's body |
| 6 | `JS-BuildAIGuardScanBody` | assemble `{content, direction, …}` |
| 7 | `AM-SetAIGuardScanRequest` | materialise the HTTP request with the Bearer header |
| 8 | `SC-AIGuardScan` | POST `resolve-and-execute-policy` (no policy id) |
| 8b | `SC-AIGuardExecutePolicy` | POST `execute-policy` (policy id pinned) |
| 9 | `EV-ParseAIGuardVerdict` | action, severity, policyName, transactionId, statusCode, errorMsg |
| 10 | `JS-ParseDetectors` | flatten `detectorResponses` into name lists |
| 11 | `JS-ProcessVerdict` | decide allow/block, build the refusal body |
| 12 | `RF-Block` | return it |

Steps 6–11 are gated on `aiguard.shouldScan` **and** `aiguard.hasContent` **and**
`aiguard.contentCount != "0"`, so a text-less turn never sends an empty scan.

### The block path

A block is returned in the **caller's own dialect**, not as a generic error, so
an SDK client parses it instead of throwing. `JS-ProcessVerdict` picks the shape
from the request:

| Caller | Block shape |
|--------|-------------|
| Gemini / Vertex | `candidates[]` with `finishReason: STOP`, plus an `aiguard` object |
| OpenAI chat | `chat.completion` with the notice as the assistant message |
| OpenAI Responses | `response` object with `output[]` |
| Anthropic | `message` with a `text` content block |
| MCP | JSON-RPC `error` (`-32000`) |
| Streaming (any) | a graceful SSE refusal that completes the stream cleanly |

This is a real block observed on the deployed proxy:

```
HTTP/2 200
x-aiguard-blocked: true
x-aiguard-category: pii
x-aiguard-severity: CRITICAL
x-aiguard-transaction-id: 86ef7919-29a4-4948-8cc3-14ef9bec9794

{"candidates":[{"content":{"role":"model","parts":[{"text":
  "ZSCALER AI GUARD SECURITY ALERT: REQUEST BLOCKED: Sensitive personal data
   detected, Prompt injection or jailbreak attempt detected"}]},
  "finishReason":"STOP"}],
 "modelVersion":"gemini-2.5-flash",
 "aiguard":{"action":"BLOCK","severity":"CRITICAL","policyName":"PolicyRule01",
            "detectors":["pii","prompt_injection"],"transactionId":"86ef7919-…"}}
```

HTTP 200 is deliberate: the caller's SDK sees a well-formed response. The
`x-aiguard-*` headers make the block detectable, and `blockStatus` can force a
hard status (e.g. `403`) when blocks should show in status-code metrics. SSE
always stays 200, because a stream needs it.

## 4. Content extraction

`extract-content.js` walks the caller's body per dialect and collects the text.
The rule throughout is **fail toward the configured posture, never throw**: a
body the walker cannot read is reported unscannable and follows `on_unscannable`
rather than raising a 500 out of the gateway.

For tool calls the flow collects the JSON's **scalar values**, not its
serialization. This matters more than it looks. Feeding a detector
`{\"ticket_id\": \"T-1234\"}` with its braces and escapes reads as code and
false-positives benign calls; feeding it `read_ticket T-1234` reads as text. The
same mistake in the AWS integrations produced a false `pii` block on a benign
ticket lookup until the double encoding was removed.

## 5. The API contract

The detection API accepts four fields and no more:

```json
{ "content": "…", "direction": "IN|OUT", "transactionId": "uuid", "policyId": 1152 }
```

Three consequences shape the flow:

**There is no metadata field.** App name, user, model and agent identifiers
cannot ride along with the scan, so they stay in the gateway's own logs. The
transaction id is what joins a log line to the console record.

**`transactionId` must be a 36-character UUID.** Anything else returns HTTP 500.
`build-aiguard-scan-body.js` therefore sends it only when it already is a UUID
and otherwise omits the field, letting the API mint its own.

**A 200 can carry no verdict.** Soft failures arrive as HTTP 200 with an in-body
`statusCode` — `404 "Policy not found"` when `policyId` names a policy the key
cannot use. A response with no `action` is **not permission**; it is treated as
no verdict and follows the fail-closed posture, naming the cause in the message.

## 6. Verdict processing

`EV-ParseAIGuardVerdict` lifts the scalar fields with JSONPath.
`detectorResponses` needs its own policy: it is a map **keyed by detector name**,
and JSONPath cannot enumerate keys. `JS-ParseDetectors` walks it once and
publishes two comma-separated lists:

```
aiguard.triggeredDetectors   every detector that fired
aiguard.blockingDetectors    those whose action is BLOCK
```

Both are reported exactly as the API returned them. A detector can carry
`action: BLOCK` while `triggered` is false — that is the policy's configured
action, and interpreting it is the policy's job, not the gateway's.

`JS-ProcessVerdict` maps the action to an outcome:

| Action | Outcome | Why |
|--------|---------|-----|
| `ALLOW` | allow | — |
| `DETECT` | allow | monitor-only: reported and logged, not enforced |
| `BLOCK` | block | native-shape refusal |
| anything else | block | an unrecognised verdict is not permission |
| no action / non-200 | block | unless `failOpen=true` |

## 7. No masking step

The upstream reference has a mask-in-place path: its API can return a DLP-masked
rewrite of the content, which a policy writes back over the original. AI Guard
returns a **verdict**, not a rewritten payload, so there is no equivalent. The
outcome is allow or block, and the masking policies and outcome are absent by
design rather than unimplemented.

## 8. Configuration model

Config arrives from three places, in priority order: FlowCallout parameters →
proxy flow variables → the encrypted KVM. `JS-InitConfig` normalises all of it
into `aiguard.cfg.*` so no later step reads raw input.

| Variable | Default | Meaning |
|----------|---------|---------|
| `type` / `scanType` | `prompt` | phase, and therefore direction |
| `aiguardCloud` | `us1` | builds `api.<cloud>.zseclipse.net` |
| `aiguardEndpoint` | — | full host override |
| `aiguardPolicyId` | unset | pin a policy; **leave unset** |
| `failOpen` | `false` | allow when the scan cannot complete |
| `blockStatus` | `native` | or a numeric status for metrics |
| `appName` | `Gateway` | log identity |

> Leaving `aiguardPolicyId` unset is not just a default, it is the recommended
> posture: the API resolves the policy bound to the key, and a stale id fails
> closed in a way that is easy to misread as a scanning failure.

## 9. Why fail-closed

A gateway security control that allows traffic when it cannot get a verdict is
worse than no control, because it looks like protection. Every path that cannot
produce a verdict blocks: missing API key, unreachable API, non-200 callout,
missing action, unrecognised action. `failOpen=true` exists for teams who
consciously prefer availability, and it is explicit.

## 10. Testing

```bash
node ZSCALER-AIGUARD/test/run-unit.js
```

Runs the bundle's JavaScript under Node with a stubbed Apigee `context`, covering
the parts that are pure logic and where a porting mistake actually lands: config
resolution, scan-body construction, detector flattening and the verdict decision
— including that DETECT passes, an unknown action blocks, and a soft `404
"Policy not found"` names its cause. 30 checks.

For the deployed proxy, see
[`../../cloudrun/flow/scripts/test_deployed.py`](../../cloudrun/flow/scripts/test_deployed.py).

## 11. Extending this

**A new caller dialect** — add a branch to `llmFlavor()` and `buildBlock()` in
`process-verdict.js`, and extraction in `extract-content.js`.

**A new detector** — nothing to change. Detector names come from the API and
unknown ones fall back to their own name in the block message. Add a friendly
label to `descriptions` in `init-config.js` if you want prose.

**A different scan target** — `SC-AIGuardScan` templates its host from
`aiguard.cfg.endpoint`; region selection needs no bundle change.

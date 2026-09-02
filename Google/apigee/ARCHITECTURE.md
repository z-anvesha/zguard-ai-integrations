# Architecture — Apigee X + Vertex AI + Zscaler AI Guard

How the `vertex-aiguard` proxy works, and why it is shaped this way. For setup
and usage see [README.md](README.md). For the reusable-flow variant, see
[`sharedflow/ARCHITECTURE.md`](sharedflow/ARCHITECTURE.md).

## 1. Big picture

```
   caller                Apigee X                    Vertex AI
     │                      │                            │
     │  POST /vertex        │                            │
     ├─────────────────────►│                            │
     │                      │ 1. KVM: API key            │
     │                      │ 2. extract prompt text     │
     │                      │ 3. POST resolve-and-       │
     │                      │    execute-policy  IN ─────┼──► AI Guard
     │                      │◄───── ALLOW / BLOCK ───────┼───
     │                      │                            │
     │                      │ ALLOW ─────────────────────►│  generateContent
     │                      │◄────────────── candidates[] │  (GoogleAccessToken)
     │                      │                            │
     │                      │ 4. extract response text   │
     │                      │ 5. POST …  OUT ────────────┼──► AI Guard
     │                      │◄───── ALLOW / BLOCK ───────┼───
     │◄─────────────────────┤                            │
     │  200 candidates[]    │  or 403 + x-aiguard-*      │
```

Everything lives in one proxy bundle: fourteen policies, two JavaScript
resources, one target. Nothing is shared with any other proxy, and there is
nothing else to deploy.

## 2. apiproxy vs sharedflow

Both do the same scanning. They differ only in **where the policies live**.

This proxy carries them inline. That is the smaller footprint and the shorter
trace — one artefact, one deploy, no cross-bundle version skew. The cost shows
up on the second proxy: adding one means copying eleven policies, and a fix to
the scan logic has to be applied in every copy.

The [SharedFlow](sharedflow) inverts that. The scanning bundle is deployed once
and any proxy invokes it with a two-line `FlowCallout`. Two artefacts instead of
one, and one more hop in the trace, but the logic exists in exactly one place.

| | Inline proxy (this one) | SharedFlow |
|---|---|---|
| Bundles to deploy | 1 | 2 |
| Cost of a second proxy | copy 14 policies | 2 lines |
| Fixing the scan logic | edit every proxy | edit one bundle |
| Callers understood | Vertex / Gemini | Gemini, OpenAI, Anthropic, MCP, SSE |
| Block shape | `403` + JSON error | the caller's own dialect, `200` |
| Best for | a single LLM proxy | a shared posture across proxies |

Pick this one to protect one Vertex endpoint. Pick the SharedFlow when a second
proxy is on the roadmap, or when callers speak more than the Gemini dialect.

## 3. Network architecture

Apigee X runtime instances come in two connectivity shapes, and the choice is
made at instance-creation time and cannot be changed afterwards.

**With VPC peering** the instance gets a routable address reachable from peered
networks, and the environment group hostname resolves normally.

**With `disableVpcPeering`** — what `provision_org.py` creates, and what the
evaluation org used here runs — the instance has **no public hostname at all**.
It publishes a *service attachment*, and reaching it means creating a Private
Service Connect endpoint inside your own VPC:

```
   your VPC (default, us-west1)
   ┌────────────────────────────────────────────┐
   │  test VM  10.138.0.3                       │
   │      │                                     │
   │      │ https://<envgroup-hostname>/vertex  │
   │      │ --resolve <hostname>:443:10.138.0.100
   │      ▼                                     │
   │  forwarding rule  10.138.0.100  ───────────┼──► service attachment
   └────────────────────────────────────────────┘         │
                                                          ▼
                                                   Apigee runtime
```

Two consequences worth knowing before debugging a connection:

- **The envgroup hostname resolves nowhere in DNS.** It is a routing key, not an address. Callers reach the endpoint by IP and present the hostname in SNI/Host — which is what `curl --resolve` does, and what a load balancer would do for you in production.
- **The evaluation certificate does not match a placeholder hostname**, so a test client needs `-k`. For real traffic, front the PSC endpoint with an external HTTPS load balancer holding a certificate for a name you actually own.

[`../cloudrun/flow/scripts/test_deployed.py`](../cloudrun/flow/scripts/test_deployed.py)
drives requests from a VM inside that VPC over IAP, so no public ingress is
needed to test.

## 4. Policy execution order

`proxies/default.xml` runs fourteen steps, eight inbound and six outbound.

| # | Policy | Flow | Purpose |
|---|--------|------|---------|
| 1 | `KVM-GetConfig` | request | API key, cloud, policy id, project, model from the encrypted KVM |
| 2 | `RF-ConfigError` | request | fail-closed guard: no API key means no traffic |
| 3 | `JS-ScanPrompt` | request | pull prompt text out of the Gemini body, build the scan payload |
| 4 | `AM-AIGuardRequest` | request | materialise the HTTP request with the Bearer header |
| 5a | `SC-AIGuardScan` | request | POST `resolve-and-execute-policy`, `direction=IN` (no policy id) |
| 5b | `SC-AIGuardExecutePolicy` | request | POST `execute-policy` instead (policy id pinned) |
| 6 | `EV-AIGuardVerdict` | request | lift action, severity, policyName, transactionId, statusCode, errorMsg |
| 7 | `RF-Block` | request | 403 unless the verdict is an explicit ALLOW or DETECT |
| 8 | `JS-ScanResponse` | response | pull the answer text out of `candidates[]` |
| 9 | `AM-AIGuardResponseRequest` | response | build the outbound scan request |
| 10a | `SC-AIGuardResponseScan` | response | POST `resolve-and-execute-policy`, `direction=OUT` |
| 10b | `SC-AIGuardResponseExecutePolicy` | response | POST `execute-policy` instead |
| 11 | `EV-AIGuardResponseVerdict` | response | lift the same fields |
| 12 | `RF-BlockResponse` | response | 403 on the same rule |

Steps 4–7 are gated on `aiguard.prompt.present` and steps 9–12 on
`aiguard.response.present`, so a turn carrying no text is never scanned — and,
just as importantly, is never blocked for lacking a verdict on nothing.

Each leg has two callouts because the two endpoints are not interchangeable, and
both write the same response variable so the `EV-` policy after them does not
care which one ran.

### The `Set` child order trap

`RaiseFault`'s `FaultResponse/Set` children must appear in schema order:
`Headers`, `Payload`, `StatusCode`, `ReasonPhrase`. Out of order, Apigee
silently discards the whole `FaultResponse` and returns its own envelope:

```
HTTP/2 500
{"fault":{"faultstring":"Raising fault. Fault name : RF-Block", …}}
```

The block still happens — the request never reaches Vertex — but the caller sees
an opaque 500 instead of the documented 403. It is worth checking first whenever
a block returns the wrong shape, because nothing in the deploy output flags it.

## 5. Authentication

Two independent credential chains, neither of which involves a secret in the
bundle.

**To Vertex AI** — the `GoogleAccessToken` element on the target endpoint mints
an OAuth token at request time from the proxy's deployment service account. The
proxy is deployed with `?serviceAccount=…`, and that account needs
`roles/aiplatform.user`. The Apigee service agent needs
`roles/iam.serviceAccountTokenCreator` on it to do the minting.

**To AI Guard** — a Bearer token read from the encrypted environment KVM at
request time by `KVM-GetConfig` and set as a header by `AM-AIGuardRequest`. It
is never written to a flow variable that leaves the proxy and never appears in
the bundle.

The policy id is deliberately **not** caller-controllable. An earlier revision
honoured an `X-AIGuard-Policy` request header; that let any caller name a policy
that does not resolve, which — see below — used to mean no scan at all.

## 6. Blocking logic

The rule is stated once and applied on both legs:

> Block unless the verdict is an explicit `ALLOW`, or the monitor-only `DETECT`.

| Situation | Outcome |
|-----------|---------|
| `action: ALLOW` | allow |
| `action: DETECT` | allow — monitor-only: reported and logged, not enforced |
| `action: BLOCK` | 403 |
| any other action | 403 — an unrecognised verdict is not permission |
| HTTP 200, no `action` at all | 403 |
| non-200 from the scan callout | 403 |
| callout timed out or could not connect | the flow faults; Vertex is never called |
| no API key configured | 500 from `RF-ConfigError`, before any scanning |

The two rows that matter are the ones that look like success. A verdict-less
200 is the shape a soft failure takes, and the earlier condition —
`aiguard.action = "BLOCK"` — read it as permission. A gateway that allows
traffic whenever it cannot get a verdict is worse than no gateway, because it
looks like protection.

A block on the wire:

```
HTTP/2 403
x-aiguard-blocked: true
x-aiguard-severity: CRITICAL
x-aiguard-transaction-id: 385abf8c-f927-45a5-9714-5ebbfeaa9093

{"error":"ZSCALER AI GUARD: REQUEST BLOCKED","direction":"IN","action":"BLOCK",
 "severity":"CRITICAL","policy":"PolicyRule01",
 "transaction_id":"385abf8c-f927-45a5-9714-5ebbfeaa9093",
 "scan_status":"200","scan_detail":""}
```

`scan_status` and `scan_detail` carry the API's **in-body** status and message,
which is where a soft failure explains itself. Pinning a policy id that does not
resolve produces exactly that, on a prompt with nothing wrong with it:

```
HTTP/2 403
x-aiguard-blocked: true

{"error":"ZSCALER AI GUARD: REQUEST BLOCKED","direction":"IN","action":"",
 "severity":"","policy":"",
 "transaction_id":"b909366d-dbdf-44ee-9d98-fb6acc91b4eb",
 "scan_status":"404","scan_detail":"Policy not found"}
```

Empty `action`, `severity` and `policy` are the tell: no verdict was reached, so
nothing was permitted. `scan_detail` names why.

## 7. The API contract

The detection API accepts four fields and no more:

```json
{ "content": "…", "direction": "IN|OUT", "transactionId": "uuid", "policyId": 1152 }
```

**There is no metadata field.** Session id, model and caller identity cannot ride
along with the scan, so they stay in the gateway's own logs. The transaction id
is the join key between a gateway log line and the AI Guard console record.

**A 200 can carry no verdict.** Soft failures arrive as HTTP 200 with an in-body
`statusCode` — `404 "Policy not found"` when `policyId` names a policy the key
cannot use. Hence the blocking rule above.

**Which endpoint gets called** depends on one KVM entry:

| `aiguard_policy_id` | Endpoint | Behaviour |
|--------------------|----------|-----------|
| unset (recommended) | `/v1/detection/resolve-and-execute-policy` | the API resolves the policy bound to the key |
| set | `/v1/detection/execute-policy` | that exact policy, or a soft 404 |

The two endpoints need separate callouts because **`resolve-and-execute-policy`
ignores `policyId` outright** — it does not error on an id it cannot use, it
resolves the key's own policy and answers normally. Sending a pinned id to the
resolve endpoint therefore looks like it works while quietly scanning against a
different policy than the one asked for.

> ⚠️ Leaving it unset is the recommended posture, not just the default. A stale
> id fails closed in a way that reads like a scanning outage rather than a typo.

## 8. Scanning coverage

`JS-ScanPrompt` walks `contents[].parts[].text` and `JS-ScanResponse` walks
`candidates[].content.parts[].text`, concatenating the text and nothing else.
Both fall back to the raw body if it will not parse, so a body the walker cannot
read still gets scanned rather than silently skipped.

That is the full extent of it: this proxy understands the Gemini dialect only.
Streaming, tool calls, and OpenAI/Anthropic/MCP request shapes are the
[SharedFlow](sharedflow)'s job.

## 9. No masking step

The upstream reference this pattern follows has a mask-in-place path: its API can
return a DLP-masked rewrite of the content, which a policy writes back over the
original. AI Guard returns a **verdict**, not a rewritten payload, so there is no
equivalent. The outcome is allow or block, and the masking policies are absent by
design rather than unimplemented.

## 10. Latency

Two scans per request, each a synchronous call to the AI Guard API, on the
critical path. Roughly 100–300 ms per leg, so 200–600 ms added to a round trip.
The callout timeouts — 5 s inbound, 6 s outbound — bound the worst case; a
timeout faults the flow, which on the request leg means Vertex is never called.

## 11. Extending this

**Another model or region** — the target URL templates `{private.vertex.project}`
and `{private.vertex.model}` from the KVM; the location is hard-coded to
`us-central1` in `targets/vertex-target.xml`.

**Another caller dialect** — extend `scan-prompt.js` and `scan-response.js`, or
switch to the [SharedFlow](sharedflow), which already handles four.

**Detector names in the block message** — this proxy reports severity and policy
but not which detectors fired. `detectorResponses` is a map keyed by detector
name, and Apigee's JSONPath cannot enumerate keys; the SharedFlow's
`JS-ParseDetectors` walks it in JavaScript instead.

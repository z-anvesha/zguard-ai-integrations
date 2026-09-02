# Google Cloud Integrations for Zscaler AI Guard

Integrations between Google Cloud AI services and **Zscaler AI Guard**, scanning
prompts and model responses at the API gateway so enforcement happens before a
request reaches Vertex AI — and before a response reaches the caller.

## Overview

| Integration | Pattern | Best for |
|-------------|---------|----------|
| [apigee/apiproxy](./apigee) | Self-contained proxy with the scanning policies inline | A single LLM proxy; simplest footprint |
| [apigee/sharedflow](./apigee/sharedflow) | Reusable `ZSCALER-AIGUARD` SharedFlow + a thin proxy that calls it | Several proxies sharing one AI Guard posture |
| [cloudrun/flow](./cloudrun/flow) | Git-push pipeline that provisions the SharedFlow pattern | Automating the above, no manual gcloud |
| [cloudrun/proxy](./cloudrun/proxy) | Same pipeline for the self-contained proxy | Automating the inline pattern |

## Which one

**Inline proxy vs SharedFlow** is the real choice; the Cloud Run folders just
automate deploying whichever you pick.

The inline proxy carries its policies inside the proxy bundle. One artefact, one
deploy, nothing to coordinate — and every additional proxy is a copy of the same
policies, so a fix has to be applied in each.

The SharedFlow is deployed once and invoked from any proxy with a two-line
FlowCallout. Two artefacts instead of one, and an extra hop in the trace, but the
scanning logic lives in exactly one place.

| | Inline proxy | SharedFlow |
|---|---|---|
| Bundles to deploy | 1 | 2 |
| Cost of a second proxy | copy all policies | 2 lines |
| Fixing scan logic | edit every proxy | edit one bundle |

## How scanning maps onto AI Guard

Each leg is one call to the detection API:

| Leg | Direction | Catches |
|-----|-----------|---------|
| prompt | `IN` | Prompt injection, secrets and PII heading to the model |
| tool arguments | `IN` | Sensitive data leaving for an external tool |
| tool results | `OUT` | Indirect injection and leakage re-entering the model |
| response | `OUT` | Data loss and unsafe content the model produced |

With no policy id configured — the recommended posture — the call goes to
`/v1/detection/resolve-and-execute-policy` and the API resolves the policy bound
to your key. Setting `aiguardPolicyId` switches to `/v1/detection/execute-policy`
against that exact id.

> ⚠️ **Leave the policy id unset unless you have a specific reason.** An id that
> does not exist for your key returns `"Policy not found"` **inside an HTTP 200**
> — easy to miss. The integrations treat a response with no action as no verdict
> and fail closed on it.

## Blocks look like the caller's own API

A refusal is returned in the dialect the caller speaks, not as a generic error,
so an SDK client parses it instead of throwing. Gemini callers get a
`candidates[]` envelope, OpenAI callers a `chat.completion`, Anthropic callers a
`message`, MCP callers a JSON-RPC error, and streaming callers a graceful SSE
refusal that completes the stream.

From a deployed proxy:

```
HTTP/2 200
x-aiguard-blocked: true
x-aiguard-severity: CRITICAL
x-aiguard-transaction-id: 86ef7919-29a4-4948-8cc3-14ef9bec9794

{"candidates":[{"content":{"role":"model","parts":[{"text":
  "ZSCALER AI GUARD SECURITY ALERT: REQUEST BLOCKED: Sensitive personal data
   detected, Prompt injection or jailbreak attempt detected"}]},
  "finishReason":"STOP"}],
 "aiguard":{"action":"BLOCK","detectors":["pii","prompt_injection"], …}}
```

HTTP 200 keeps SDK clients working; the `x-aiguard-*` headers make the block
detectable, and `blockStatus` can force a hard status when blocks should appear
in status-code metrics.

## Enforcement posture

Fail-closed by default. A missing API key, an unreachable API, a non-200 from the
scan callout, a response carrying no action, and any verdict the flow does not
recognise all block. `failOpen=true` is the explicit opt-out, and `DETECT` is AI
Guard's monitor-only verdict: reported, not enforced.

## Getting started

No Apigee org yet? The pipelines configure an org, they do not create one:

```bash
python3 cloudrun/flow/setup/provision_org.py --project=YOUR_PROJECT_ID --region=us-west1
```

That creates the org, runtime instance, environment, environment group and both
attachments. Two things that bite:

- **The region must match any existing API Hub instance** in the project, or the API refuses with *"an API Hub instance already exists in location X"*.
- **The runtime instance takes 20–40 minutes** and is visible as `CREATING` long before it is usable; attaching an environment too early fails with *"the resource is locked by another operation"*.

Then deploy:

```bash
cd cloudrun/flow
python3 setup/bootstrap.py --project=YOUR_PROJECT_ID --region=us-west1 --apigee-env=eval
gcloud builds submit --config=cloudbuild.yaml --region=global ../../..
```

And test:

```bash
python3 scripts/test_deployed.py --samples
```

## Reaching the proxy

An Apigee instance created with `disableVpcPeering` has **no public hostname** —
it is reachable only through a Private Service Connect endpoint inside your VPC:

```bash
gcloud compute addresses create aiguard-apigee-psc-ip --region=us-west1 --subnet=default
gcloud compute forwarding-rules create aiguard-apigee-psc --region=us-west1 \
  --network=default --address=aiguard-apigee-psc-ip \
  --target-service-attachment=$(gcloud apigee ... instances describe ... --format='value(serviceAttachment)')
```

Call it from a VM in that VPC, or front it with an external HTTPS load balancer
and a real certificate for public access. `scripts/test_deployed.py` does the
former over IAP.

## Everything is Python

The provisioning and test scripts use only the Python standard library plus
`gcloud`. There is no `jq`, no `zip`, no shell script, and no pip install — which
also keeps the provisioner image to a bare `google/cloud-sdk:slim`.

## IMPORTANT

The contents of this repository are community examples and reference
implementations, supported as best effort by Zscaler. They are intended as
starting points to illustrate integration patterns — review, adapt, and validate
them for your own environment before any production use.

## Resources

- [Zscaler AI Guard](https://www.zscaler.com/products/ai-guard)
- [AI Guard documentation](https://help.zscaler.com/ai-guard)
- [Apigee X](https://cloud.google.com/apigee/docs)
- [Vertex AI](https://cloud.google.com/vertex-ai/docs)

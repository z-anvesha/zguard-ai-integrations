# Kong Gateway — Zscaler AI Guard

Two ways to enforce AI Guard on traffic passing through Kong. Both scan the
prompt on the way in and the LLM response on the way out, and both fail closed
when a verdict cannot be reached.

| | [`custom-plugin/`](custom-plugin) | [`request-callout/`](request-callout) |
|---|---|---|
| Kong flavour | Self-managed (Gateway / OSS) | Konnect (SaaS) |
| Form | Lua plugin — `handler.lua`, `schema.lua` | declarative Request Callout config |
| Install | drop into the plugin path, enable per service or route | apply a config; nothing to install |
| Use when | you control the Kong nodes and can ship Lua | you are on Konnect and cannot |

Konnect does not permit custom Lua, which is the whole reason the second form
exists — it expresses the same two scans using the built-in Request Callout
plugin instead.

## How scanning maps onto AI Guard

Each leg is one call to the detection API:

| Leg | Direction | Catches |
|-----|-----------|---------|
| prompt | `IN` | Prompt injection, secrets and PII heading to the model |
| response | `OUT` | Data loss and unsafe content the model produced |

With no policy id configured — the recommended posture — the call goes to
`/v1/detection/resolve-and-execute-policy` and the API resolves the policy bound
to your key.

> ⚠️ **Leave the policy id unset unless you have a specific reason.** An id that
> does not exist for your key returns `"Policy not found"` **inside an HTTP 200**
> — a response with no action is treated as no verdict and fails closed.

## Enforcement posture

Fail-closed: a missing API key, an unreachable API, a non-200 from the scan, a
response carrying no action, and any verdict not recognised all block. `DETECT`
is AI Guard's monitor-only verdict — reported, not enforced.

## Getting started

Pick the folder that matches your Kong deployment and follow its README:

- **[custom-plugin/README.md](custom-plugin/README.md)** — the Lua plugin
- **[request-callout/README.md](request-callout/README.md)** — the Konnect callout

Both need an AI Guard API key from the AI Guard Console → Private AI Apps → App
API Keys, and the cloud region your tenant runs in (`us1`, `us2`, `eu1`, `eu2`).

## Resources

- [Zscaler AI Guard](https://www.zscaler.com/products/ai-guard)
- [Kong Gateway plugin development](https://developer.konghq.com/custom-plugins/)
- [Kong Request Callout](https://developer.konghq.com/plugins/request-callout/)

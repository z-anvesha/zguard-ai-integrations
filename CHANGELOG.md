# Zscaler AI Guard Integrations Changelog

## 0.2.0 (September 1, 2026)

### Notes

- Python Versions: **v3.11, v3.12, v3.13**
- **Breaking:** all Python integrations now require `zscaler-sdk-python>=1.9.44`. Earlier releases never attached the Bearer token to AI Guard policy-detection calls, so every scan failed with `401 Unauthorized`.
- **Behavioral:** enforcement is now uniformly fail-closed, and `DETECT` is uniformly monitor-only. Integrations that previously allowed traffic on a failed scan now block it; integrations that blocked on `DETECT` now allow it. This includes the Claude Code hooks, which previously allowed on API errors by design — if AI Guard is unreachable, Claude Code now stops until it is reachable. See Bug Fixes.

### Features

- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - **OpenAI Codex CLI** — new integration with six Python hooks covering `UserPromptSubmit`, `PreToolUse` (Bash and MCP), `PostToolUse` (Bash and MCP), and `Stop`
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - **AWS** — new integration with four stdlib-only components: a Bedrock AgentCore wrapper, a Lambda decorator, boto3 `before-call`/`after-call` hooks, and a Strands Agents `HookProvider`
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - **Google Apigee X** — new `ZSCALER-AIGUARD` SharedFlow (13 policies, 7 ES5 JS resources) covering the Gemini, OpenAI, Anthropic, MCP and SSE dialects, plus a thin `vertex-aiguard-sync` proxy
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - **Google Cloud Run** — two Cloud Build → Cloud Run Job pipelines that provision either Apigee pattern, and `provision_org.py`, which creates an Apigee org from scratch
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Added `aiguard_utils.py` for Codex with a configuration self-check reporting `.env` discovery, resolved settings, and a live test scan
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Added `--dry-run` to the Jenkins model deploy and undeploy scripts, so both are verifiable without provisioning GPUs

### Enhancements

- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Pinned `zscaler-sdk-python>=1.9.44` across all `requirements.txt` files
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Added `ARCHITECTURE.md` for both Apigee patterns, covering the request lifecycle, the Private Service Connect topology a `disableVpcPeering` instance requires, and when to pick the inline proxy over the SharedFlow
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Converted the last shell scripts in the repository to Python — AWS deploy/teardown to boto3, and Jenkins `deploy_model.sh`/`undeploy_model.sh` — removing the AWS CLI, `jq` and `zip` as dependencies
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Aligned the Apigee inline proxy on the `aiguard-config` KVM, so one provisioned environment serves the inline proxy, the SharedFlow and both Cloud Run pipelines
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Added `make compile-openai`, `compile-aws` and `compile-google`, and wired them into `make test-compile` and the weekly CI, which did not cover the new integrations
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Documented `AIGUARD_POLICY_ID` as a footgun: a stale ID returns `"Policy not found"` inside an HTTP 200, which now fails closed
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Documented that the Jenkins pipeline never undeploys the model endpoint, so GPU cost continues until `undeploy_model.py` is run
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Replaced the destructive `cp settings.json ~/.claude/settings.json` install step with a non-destructive merge
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Documented the two Claude Code hook blocking contracts: `UserPromptSubmit` exits 2 while `PreToolUse`/`PostToolUse` emit JSON on stdout
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Added troubleshooting for policies that block unconditionally and for direction `IN` vs `OUT` verdict mismatches

### Bug Fixes

#### Enforcement

- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - **Fixed fail-open enforcement across every integration.** A response with no `action` — from a missing key, an unreachable API, or `"Policy not found"` returned inside an HTTP 200 — was read as permission. Every path that cannot produce a verdict now blocks
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Kong Lua plugin comparing the API's upper-case verdict against lower-case `"allow"`, which blocked **all** traffic including allowed content
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Kong Konnect request-callout matching a lower-case `"block"` against an API that answers in upper case, so it **never** blocked
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Azure APIM fragment, LiteLLM callback, TrueFoundry server, n8n workflow and Anthropic skill blocking only on an explicit `BLOCK`, so a verdict-less response passed
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Claude Code hooks (`scan_user_input`, `scan_url`, `scan_mcp_request`, `scan_response`) allowing on a missing API key, an API error, or an exception — a 401 from a revoked key passed traffic unscanned
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed Cursor's `scan_response.py` — the hook that sees indirect injection in MCP tool output — allowing output through whenever a scan failed or returned no verdict
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Apigee inline proxy blocking only on an explicit `BLOCK`, letting a soft `404 "Policy not found"` pass unscanned traffic to Vertex AI
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Changed the shipped Cursor `hooks.json.example` from `failClosed: false` to `true`, so a crashed or timed-out hook no longer silently allows the action it was meant to scan
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Removed the `action = r.get("action") or "ALLOW"` default from all Cursor, Cline and Windsurf hooks, which defeated the no-verdict guard immediately below it
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Made `DETECT` uniformly monitor-only across Kong, NeMo Guardrails and the Portkey examples, which blocked on it and so turned a monitoring policy into an enforcing one

#### API contract

- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed `ImportError: cannot import name 'LegacyZGuardClient'` across all Python integrations — the class is `LegacyAIGuardClient`, reached via `client.aiguard.policy_detection`
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed `ModuleNotFoundError: zscaler.zaiguard` in LiteLLM, NeMo Guardrails, Portkey and TrueFoundry — the module is `zscaler.aiguard.legacy`
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed Kong sending `transaction_id`; the field is `transactionId` and was being silently dropped, losing console correlation
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed non-UUID `transactionId` values causing HTTP 500 — they are now hashed with `uuid5` or omitted
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Apigee inline proxy sending `policyId` to `resolve-and-execute-policy`, which ignores it outright; a pinned ID now routes to `execute-policy`
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed tool-call payloads being double-encoded before scanning, which showed detectors JSON braces and escapes and produced false `pii` blocks
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Removed `auto_retry_on_rate_limit` and `max_rate_limit_retries` from client configs — `LegacyAIGuardClient` silently discards them

#### Configuration and deployment

- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Apigee `RaiseFault` policies returning Apigee's default HTTP 500 envelope instead of the documented 403 — `FaultResponse/Set` children must be ordered `Headers`, `Payload`, `StatusCode`, `ReasonPhrase`
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Removed the `X-AIGuard-Policy` request header from the Apigee proxy, which let any caller pin a policy ID that does not resolve
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Cloud Run proxy pipeline writing KVM keys the inline bundle never read, so the deployed proxy could not find its API key, cloud region, or Vertex project and model
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Cloud Run proxy pipeline's smoke-test URL and README example, which used the SharedFlow's Vertex-style path and returned HTTP 404 against the inline proxy's `/vertex` basepath
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed the Apigee `RF-ConfigError` message naming the pre-rename KVM map and key
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed Jenkins endpoint cleanup matching display names with gcloud's `~` regex operator instead of equality, which could delete unrelated endpoints
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed `scan_response.py` returning a 5-tuple on the missing-key path while its caller unpacked 6, crashing the hook with `ValueError` instead of reporting the misconfiguration
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed `SECURITY_LOG_PATH` not expanding `~`, which created a directory literally named `~` and hid every log entry
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed an unhandled `ValueError` on a quoted `AIGUARD_POLICY_ID`, which crashed every Claude Code hook
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Wired `scan_file_read.py` into the shipped Claude Code `settings.json`; the hook, its README and its tests all existed but it was never registered, so it never ran
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed `scan_file_read.py` reading `tool_input.path` instead of `tool_input.file_path`, so file-read scanning never ran
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Corrected the Codex hooks feature flag from `codex_hooks` to `hooks`

#### Documentation

- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Corrected the Cursor README, which documented the hooks as failing open when three of the four already blocked
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Corrected the Kong request-callout README, which documented the API as returning lower-case `allow`/`block` and the `transaction_id` field name
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Fixed five dead links in the root `README.md`: moved `ARCHITECTURE.md` and `AGENTIC_AI_INTEGRATION.md` out of the gitignored `local_dev/` into a new `docs/` folder, added a `Kong/README.md` index, and dropped a link to a development-only setup summary
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Moved the NeMo Guardrails `library-plugin/` out of `local_dev/`, where the README linked to it but it never shipped
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Corrected the Claude Code READMEs, which documented the hooks as failing open by design
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Added an Enforcement Posture section to the root `README.md`, covering the fail-closed table, the verdict-less HTTP 200, and the audit-only exceptions
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Corrected `docs/ARCHITECTURE.md`, which showed the non-existent `LegacyZGuardClient` class, pinned a policy id that does not resolve, and listed as planned seven integrations that already ship
- [PR #11](https://github.com/zscaler/zguard-ai-integrations/pull/11) - Updated `CLAUDE.md`, which had no AWS entry and described Google as a single Vertex proxy

## 0.1.2 (April 9, 2026)

### Notes

- Python Versions: **v3.11, v3.12, v3.13**

### Features

- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Added Anthropic Claude Code Skill integration with on-demand `/aiguard` scanning via `scan.py`
- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Added complete AI Guard detector reference (`threat-categories.md`) covering 19 prompt and 21 response detectors

### Enhancements

- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Enhanced SKILL.md auto-invoke triggers for brand safety, competitor mentions, intellectual property, invisible text, and language/topic policies
- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Updated `CLAUDE.md` with Claude Code skill entry, integration patterns, per-integration details, and key files reference
- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Fixed Malicious URL detector categorization from Content Moderation to Security in SKILL.md

### Bug Fixes

- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Fixed `CLAUDE.md` directory reference from `Azure/` to `Microsoft/`
- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Removed stale "Planned" entries for Cursor and LiteLLM from `Anthropic/README.md`

## 0.1.1 (March 31, 2026)

### Notes

- Python Versions: **v3.11, v3.12, v3.13**

### Enhancements

- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Added LiteLLM output scanning (`async_post_call_success_hook`) to SDK-based custom callback
- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Added LiteLLM native guardrail configuration example (`config-native-guardrail.yaml`)
- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Updated root `README.md` with official docs links for LiteLLM and Portkey native integrations

### Bug Fixes

- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Updated LiteLLM `README.md` with callout to official Zscaler AI Guard plugin page
- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Updated Portkey `README.md` with callout to official Zscaler AI Guard integration page
- [PR #8](https://github.com/zscaler/zguard-ai-integrations/pull/8) - Updated Portkey `examples/README.md` directing users to native plugin as recommended approach

## 0.1.0 (March 31, 2026)

### Notes

- Python Versions: **v3.11, v3.12, v3.13**

### Features

- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) - **Anthropic (Claude Code)** — Python hooks for pre/post prompt and tool-use scanning via the AI Guard DAS API.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) - **Azure API Management** — Gateway policy patterns to scan AI requests and responses at the edge.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **Cursor IDE** — Project hooks for prompts, MCP, tool use, and agent responses.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **Cline (VS Code)** — Extension hook scripts and shared utilities for UserPromptSubmit, PreToolUse, PostToolUse, and TaskComplete.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **Windsurf** — Cascade hooks for pre/post user prompts, shell commands, MCP, and cascade completion.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **Google (Apigee + Vertex AI)** — Apigee proxy and Vertex-oriented configuration for scanning proxied LLM traffic.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **Kong Gateway** — Self-managed Lua plugin and Konnect request-callout examples for inline policy enforcement.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **LiteLLM** — Proxy custom callback using `zscaler-sdk-python` for IN/OUT scanning.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **NVIDIA NeMo Guardrails** — Custom action and library plugin wiring AI Guard into guardrails flows.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **Portkey AI Gateway** — Client-side SDK scanning and gateway-oriented examples.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **TrueFoundry** — FastAPI guardrail server that delegates scans to AI Guard.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **GitHub Actions** — CI/CD policy validation pipeline (`scan_policy.py`, test prompts, workflow samples).
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7) **Jenkins** — Declarative pipeline parity with GitHub Actions for policy validation.
- [PR #7](https://github.com/zscaler/zguard-ai-integrations/pull/7)**n8n** — Custom workflow node (TypeScript) and example workflows for automation.

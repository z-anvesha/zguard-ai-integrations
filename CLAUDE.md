# Zscaler AI Guard Integrations

Integration repository for connecting **Zscaler AI Guard** with third-party AI gateways, LLM platforms, and automation tools. Each integration scans prompts and LLM responses via the AI Guard DAS API (`resolve-and-execute-policy`) to enforce DLP, content safety, PII detection, secrets scanning, and compliance policies.

## Repository Purpose

Working code, configuration examples, and documentation for deploying Zscaler AI Guard across the AI ecosystem. Where possible, integrations use **`zscaler-sdk-python`** (`LegacyZGuardClientHelper`) for direct SDK-based API calls rather than raw HTTP.

## Structure

```
├── Anthropic/          # Claude Code hooks (pre/post scan) + Claude Code skill (on-demand /aiguard scanner)
├── OpenAI/             # Codex CLI hooks (user input, bash command/response, MCP request/response, stop)
├── Microsoft/          # Azure API Management policy integration
├── Cursor/             # Cursor IDE hooks (beforeSubmitPrompt, beforeMCPExecution, postToolUse, afterAgentResponse)
├── Cline/              # Cline VS Code hooks (UserPromptSubmit, PreToolUse, PostToolUse, TaskComplete)
├── Windsurf/           # Windsurf Cascade hooks (pre/post prompt, command, MCP, cascade response)
├── AWS/                # Bedrock AgentCore wrapper, Lambda decorator, boto3 SDK hooks, Strands Agents (stdlib only)
├── Google/             # Apigee X (inline proxy + reusable SharedFlow) and Cloud Run provisioning pipelines
├── Kong/               # Kong Gateway — Lua custom plugin & Konnect request callout
├── LiteLLM/            # LiteLLM proxy — Python custom callback (zscaler-sdk-python)
├── NemoGuardrails/     # NVIDIA NeMo Guardrails — custom action + library plugin (zscaler-sdk-python)
├── Portkey/            # Portkey AI Gateway — client-side SDK scanning (zscaler-sdk-python)
├── TrueFoundry/        # TrueFoundry — custom guardrail server via FastAPI (zscaler-sdk-python)
├── github-actions/     # GitHub Actions CI/CD — policy validation pipeline (zscaler-sdk-python)
├── Jenkins/            # Jenkins Declarative Pipeline — policy validation (zscaler-sdk-python)
├── n8n/                # n8n workflow automation — custom TypeScript node
```

### Integration Patterns

| Pattern | Language | Used By |
|---------|----------|---------|
| Python SDK callback/action | Python | LiteLLM, NemoGuardrails, Portkey, TrueFoundry |
| Lua gateway plugin | Lua | Kong (self-managed) |
| Lua request callout config | Lua/YAML | Kong (Konnect SaaS) |
| TypeScript gateway plugin | TypeScript | n8n, Portkey (native plugin) |
| FastAPI guardrail server | Python | TrueFoundry |
| Claude Code hooks | Python | Anthropic |
| Codex CLI hooks | Python | OpenAI |
| Claude Code skill (on-demand scanner) | Python | Anthropic |
| Cursor IDE hooks | Python | Cursor |
| Cline IDE hooks | Python | Cline |
| Windsurf Cascade hooks | Python | Windsurf |
| CI/CD policy validation | Python | GitHub Actions, Jenkins |
| API Management policy | XML/config | Azure APIM, Google Apigee |
| Apigee SharedFlow (ES5 JS + policies) | XML/JavaScript | Google |
| Cloud Build → Cloud Run Job provisioning | Python | Google |
| Agent/SDK hooks and decorators | Python | AWS |

### Per-Integration Details

| Integration | SDK | Docker | Test Scripts | Native Plugin |
|-------------|:---:|:------:|:------------:|:-------------:|
| Anthropic (hooks) | ✅ | — | — | Python hooks |
| OpenAI (Codex hooks) | ✅ | — | ✅ | Python hooks |
| Anthropic (skill) | ✅ | — | — | Python skill + scan.py |
| Microsoft (Azure APIM) | — | — | — | Policy fragment |
| Cursor | ✅ | — | ✅ | Python hooks |
| Cline | ✅ | — | — | Python hooks |
| Windsurf | ✅ | — | — | Python hooks |
| Google (Apigee) | — | — | ✅ | Proxy + SharedFlow bundles |
| Google (Cloud Run) | — | ✅ | ✅ | Provisioning pipelines |
| AWS | — | — | ✅ | Decorator, SDK hooks, HookProvider |
| Kong | — | ✅ | ✅ | Lua plugin |
| LiteLLM | ✅ | ✅ | ✅ | Callback |
| NemoGuardrails | ✅ | — | — | Library plugin in `library-plugin/` (PR-ready) |
| Portkey | ✅ | ✅ | ✅ | TS plugin (PR-ready) |
| TrueFoundry | ✅ | ✅ | ✅ | FastAPI server |
| GitHub Actions | ✅ | — | ✅ | Policy validation |
| Jenkins | ✅ | — | ✅ | Policy validation |
| n8n | — | ✅ | — | TS node |

## Zscaler AI Guard API

All integrations call the same underlying API:

- **Endpoint**: `https://api.{cloud}.zseclipse.net/v1/detection/resolve-and-execute-policy`
- **Auth**: `Authorization: Bearer {AIGUARD_API_KEY}`
- **Payload**: `{"direction": "IN"|"OUT", "content": "text to scan"}`
- **Response fields**: `action` (ALLOW/BLOCK/DETECT), `severity`, `policyName`, `transactionId`, `detectorResponses`

### SDK Usage (preferred)

```python
from zscaler.aiguard.legacy import LegacyZGuardClientHelper

client = LegacyZGuardClientHelper(cloud="us1")
result, response, error = client.policy_detection.resolve_and_execute_policy(
    content="text to scan",
    direction="IN",
)
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `AIGUARD_API_KEY` | Yes | — | Zscaler AI Guard API key (Bearer token) |
| `AIGUARD_CLOUD` | No | `us1` | Cloud region: us1, us2, eu1, etc. |

## Working in This Repo

### Adding New Integrations

1. Create directory: `PlatformName/`
2. Include a `README.md` with: Overview, Prerequisites, Quick Start, Configuration
3. Add `examples/` with working code, `env.example`, `requirements.txt` (Python) or `package.json` (TypeScript)
4. Use `zscaler-sdk-python` when the integration supports Python
5. Provide Docker Compose for anything that needs a running server
6. Update root `README.md` with the new integration

### Technical Requirements

All integrations MUST:
1. Use `zscaler-sdk-python` **>= 1.9.44** when Python is available — either `LegacyAIGuardClient` (`client.aiguard.policy_detection`) or `LegacyZGuardClientHelper` from `zscaler.aiguard.legacy`. There is no `LegacyZGuardClient` class and no `zscaler.zaiguard` module; earlier SDK releases never attached the Bearer token and fail every scan with a 401.
   - **Exception: AWS.** Those components run inside Lambda and agent runtimes where adding a dependency is a deployment-package cost the user pays, so they call the API with `urllib` and stay stdlib-only. Keep them dependency-free.
2. Implement fail-closed logic — block when the API call fails or returns unexpected data. "Fail-closed" means blocking on anything that is not an explicit `ALLOW` or the monitor-only `DETECT`: a missing key, a transport error, a non-200, **and a 200 that carries no `action` at all**. A verdict-less 200 is how a soft failure (for example `"Policy not found"`) arrives, and reading it as permission is the defect this repo has fixed twice.
3. Support both `direction=IN` (prompt scanning) and `direction=OUT` (response scanning)
4. Never include real credentials — use `AIGUARD_API_KEY`, `AIGUARD_CLOUD` environment variables
5. Provide detailed block messages including: action, severity, policy name, transaction ID, blocking detectors

### Commit Convention

```
feat: add [Platform] integration
fix: correct [Platform] configuration
docs: update [Platform] README
test: add validation scripts for [Platform]
```

## Key Files

| File | Purpose |
|------|---------|
| `README.md` | Integration index and overview |
| `Makefile` | Local `make test-compile`, policy scans, hook sample scripts |
| `.github/workflows/weekly-integrations.yml` | Weekly Monday CI: compile + dual policy scan |
| `.github/workflows/release.yml` | Automatic GitHub releases via Conventional Commits |
| `CLAUDE.md` | This file — project context for AI agents |
| `.claude/agents.md` | Sub-agent instructions |
| `Anthropic/claude-code-skill/references/threat-categories.md` | Complete AI Guard detector reference (19 prompt + 21 response) |
| `local_dev/` | Development artifacts, plugin staging, internal docs |

## Upstream Plugin Submissions

Some integrations have native plugins ready for PR to upstream repos:

| Platform | Upstream Repo | Plugin Location | Branch |
|----------|---------------|-----------------|--------|
| NemoGuardrails | `NVIDIA-NeMo/Guardrails` | `nemoguardrails/library/zscaler_aiguard/` | `feat/zscaler-aiguard-integration` |
| Portkey | `Portkey-AI/gateway` | `plugins/zscaler-aiguard/` | `feat/zscaler-aiguard-guardrail` |

Local copies of these plugins are kept in `NemoGuardrails/library-plugin/` and `local_dev/gateway-plugin/`.

## External Resources

- [Zscaler AI Guard](https://www.zscaler.com/products/ai-guard)
- [zscaler-sdk-python](https://github.com/zscaler/zscaler-sdk-python) — `zscaler.aiguard.legacy.LegacyZGuardClientHelper`
- [NVIDIA NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails)
- [Portkey AI Gateway](https://github.com/Portkey-AI/gateway)
- [LiteLLM](https://github.com/BerriAI/litellm)
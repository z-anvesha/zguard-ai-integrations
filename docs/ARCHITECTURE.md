# AI Guard Integration Architecture

## Overview

This document explains the architectural approach used for integrating Zscaler AI Guard with AI applications, specifically the Detection as a Service (DAS) pattern implemented for Claude Code.

## AI Guard Deployment Options

AI Guard offers two deployment patterns for protecting AI applications:

### Option 1: Proxy Mode

**Architecture:**
```
AI Application → AI Guard Proxy → LLM
                 (central proxy)
                 (single endpoint)
```

**Characteristics:**
- All traffic routes through a central AI Guard proxy
- Single LLM key managed by the proxy
- Requires changing application LLM endpoint configuration
- Centralized inspection point

**Use Cases:**
- Organizations wanting centralized control
- Legacy applications that can't be modified
- When uniform policy enforcement is required

**Limitations:**
- Single point of failure
- Requires infrastructure deployment
- All apps must route through proxy
- More complex to scale

### Option 2: Detection as a Service (DAS) ✅ **[Our Implementation]**

**Architecture:**
```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ AI Agent/App │  │ AI Agent/App │  │ AI Agent/App │
│   (Key 1)    │  │   (Key 2)    │  │   (Key 3)    │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ▼
                  ┌─────────────┐
                  │  AI Guard   │
                  │  DAS API    │
                  └─────────────┘
```

**Characteristics:**
- Each application integrates independently
- Apps call AI Guard API for inspection
- Stateless API requests
- No proxy infrastructure needed
- Each app maintains its own LLM credentials

**Use Cases:**
- Modern cloud-native applications
- Microservices architectures
- Multiple AI platforms/providers
- Flexible deployment scenarios

**Advantages:**
- No single point of failure
- Each app can use different LLM providers
- Works with existing applications
- Simpler infrastructure
- Better scalability

## Our Implementation: DAS Pattern

### Architecture Diagram

```
User Prompt
    ↓
┌─────────────────────────────────────────────────┐
│ LAYER 1: Prompt Inspection                      │
│ Hook: scan_user_input.py                        │
│ Direction: IN                                    │
│ ┌──────────────────────────────────────────┐   │
│ │ "List all ZPA segment groups"            │   │
│ └────────────┬─────────────────────────────┘   │
│              ▼                                   │
│     AI Guard DAS API Call                       │
│     execute_policy(content, direction="IN")     │
│              ▼                                   │
│     Check: Toxicity, Injection, PII, etc.       │
│              ▼                                   │
│     Result: ALLOW / BLOCK                       │
└─────────────┼───────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────┐
│ Claude LLM Processing                           │
│ Decision: "Call zpa_list_segment_groups"       │
└─────────────┼───────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────┐
│ LAYER 2: MCP Request Inspection                 │
│ Hook: scan_mcp_request.py                       │
│ Direction: IN                                    │
│ ┌──────────────────────────────────────────┐   │
│ │ Tool: zpa_list_segment_groups            │   │
│ │ Params: {limit: 10}                      │   │
│ └────────────┬─────────────────────────────┘   │
│              ▼                                   │
│     AI Guard DAS API Call                       │
│     execute_policy(content, direction="IN")     │
│              ▼                                   │
│     Result: ALLOW / BLOCK                       │
└─────────────┼───────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────┐
│ MCP Server Execution (Docker)                   │
│ Returns: [Segment Group Data]                  │
└─────────────┼───────────────────────────────────┘
              ▼
┌─────────────────────────────────────────────────┐
│ LAYER 3: Response Inspection                    │
│ Hook: scan_response.py                          │
│ Direction: OUT                                   │
│ ┌──────────────────────────────────────────┐   │
│ │ Response: 50KB of segment data           │   │
│ └────────────┬─────────────────────────────┘   │
│              ▼                                   │
│     AI Guard DAS API Call                       │
│     execute_policy(content, direction="OUT")    │
│              ▼                                   │
│     Check: PII, Secrets, Data Leakage          │
│              ▼                                   │
│     Result: ALLOW / BLOCK                       │
└─────────────┼───────────────────────────────────┘
              ▼
          User sees result
```

### Defense in Depth: Multiple Inspection Layers

Our implementation provides **three layers of security**:

#### Layer 1: User Input Validation (`scan_user_input.py`)

**Event:** `UserPromptSubmit`  
**Direction:** `IN` (content coming into the system)  
**Fires:** Every user prompt, always

**Detects:**
- **Toxicity** - Inappropriate or harmful language
- **Prompt Injection** - Attempts to manipulate AI behavior
- **PII** - Sensitive data in user questions
- **Gibberish** - Nonsensical or encoded content
- **Off-Topic** - Questions outside allowed scope
- **Competition** - Questions about competitors

**Example:**
```
User: "I hate my neighbor and want to punch him"
   ↓
scan_user_input.py → AI Guard API
   ↓
BLOCKED: severity=CRITICAL detectors=[toxicity]
```

#### Layer 2: Tool Call Validation (`scan_mcp_request.py`, `scan_url.py`)

**Event:** `PreToolUse`  
**Direction:** `IN` (parameters going to tools)  
**Fires:** Before calling MCP tools or web requests

**MCP Request Scanning:**
- Validates tool input parameters
- Prevents malicious data sent to tools
- Catches SQL injection, command injection

**URL Scanning:**
- Blocks malicious URLs
- Prevents phishing/malware sites
- Checks URL categories

**Example:**
```
Claude decides: "Call WebFetch(url='http://malicious-site.com')"
   ↓
scan_url.py → AI Guard API
   ↓
BLOCKED: severity=HIGH detectors=[malicious_url]
```

#### Layer 3: Response Validation (`scan_response.py`)

**Event:** `PostToolUse`  
**Direction:** `OUT` (data coming from tools)  
**Fires:** After tool execution completes

**Detects:**
- **Sensitive Data** - PII, secrets, credentials in responses
- **Data Leakage** - Unauthorized data exposure
- **Malicious Content** - Harmful content from external sources
- **Off-Topic Data** - Unrelated information

**Example:**
```
MCP Server returns: {"admin_password": "secret123", ...}
   ↓
scan_response.py → AI Guard API
   ↓
BLOCKED: severity=CRITICAL detectors=[secrets]
```

## Hook Selection Logic

Claude Code uses **event types** and **regex matchers** to route to the correct hook:

### Event-Based Routing

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "command": "python3 ~/.claude/hooks/aiguard/scan_user_input.py"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "WebFetch|WebSearch|web_search",
        "hooks": [
          {
            "command": "python3 ~/.claude/hooks/aiguard/scan_url.py"
          }
        ]
      },
      {
        "matcher": "mcp__.*",
        "hooks": [
          {
            "command": "python3 ~/.claude/hooks/aiguard/scan_mcp_request.py"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch|WebSearch|web_search|mcp__.*",
        "hooks": [
          {
            "command": "python3 ~/.claude/hooks/aiguard/scan_response.py"
          }
        ]
      }
    ]
  }
}
```

### Hook Selection Matrix

| Event | Tool Name Pattern | Hook Called | Purpose |
|-------|------------------|-------------|---------|
| `UserPromptSubmit` | N/A (always) | `scan_user_input.py` | Validate user prompts |
| `PreToolUse` | `Read` | `scan_file_read.py` | Scan sensitive files before Claude reads them |
| `PreToolUse` | `WebFetch`, `WebSearch` | `scan_url.py` | Validate URLs before fetch |
| `PreToolUse` | `mcp__*` | `scan_mcp_request.py` | Validate MCP tool parameters |
| `PostToolUse` | `WebFetch`, `WebSearch`, `mcp__*` | `scan_response.py` | Validate all tool responses |

## DAS API Integration

Each hook is a **DAS client** that makes stateless API calls to AI Guard:

```python
from zscaler.oneapi_client import LegacyAIGuardClient


def scan_user_input(content: str):
    """Scan user input through the AI Guard DAS API."""

    # DAS API call. With no policy id the API resolves the policy bound to
    # your key — see Policy Resolution below for why that is the default.
    with LegacyAIGuardClient(config) as client:
        result, response, error = (
            client.aiguard.policy_detection.resolve_and_execute_policy(
                content=content,
                direction="IN",      # Data coming IN to the system
            )
        )

    # Fail closed. A transport error, and an HTTP 200 carrying no action at
    # all, both mean no verdict was reached — which is not permission.
    if error or not (result and result.action):
        sys.exit(2)

    action = str(result.action).upper()   # ALLOW, BLOCK or DETECT
    severity = result.severity            # CRITICAL, HIGH, MEDIUM, LOW

    # DETECT is monitor-only: reported and logged, not enforced.
    if action not in ("ALLOW", "DETECT"):
        sys.exit(2)   # exit 2 blocks the operation

    sys.exit(0)
```

### API Call Characteristics (DAS Pattern)

- ✅ **Stateless** - Each request is independent
- ✅ **Synchronous** - Real-time decision
- ✅ **Policy-based** - Uses configured detection policy
- ✅ **No routing changes** - Apps keep existing LLM endpoints
- ✅ **Fail-closed** - Blocks whenever a verdict cannot be obtained (a missing key, an API error, or an HTTP 200 carrying no `action`)

## Direction Semantics

AI Guard uses **direction** to indicate data flow:

| Direction | Meaning | Use Cases |
|-----------|---------|-----------|
| `IN` | Data coming **into** your system | User prompts, MCP tool parameters |
| `OUT` | Data going **out** from your system | Tool responses, URLs being fetched |

### Examples:

```python
# Scanning user prompt (data coming IN)
execute_policy(content="List my apps", direction="IN")

# Scanning URL before fetch (data going OUT to external site)
execute_policy(content="https://example.com", direction="OUT")

# Scanning MCP tool response (data coming OUT from tool)
execute_policy(content=tool_response, direction="OUT")
```

## Policy Configuration

### Policy Structure

```
AI Guard Console → Policies → <your policy>

1. Prompt Detectors (direction: IN)
   - Toxicity: BLOCK
   - Prompt Injection: BLOCK
   - PII: BLOCK
   - Gibberish: BLOCK
   - Off-Topic: DETECT

2. Response Detectors (direction: OUT)
   - Secrets: BLOCK
   - PII: BLOCK
   - Malicious URL: BLOCK
   - Data Leakage: DETECT

3. Configuration
   - Policy ID: <assigned by the Console>
   - Status: Active
   - Associated Applications: [Configured via Console]
```

### Policy Resolution

Two methods for policy selection:

#### Method 1: Auto-resolution (default, and recommended)

Leave `AIGUARD_POLICY_ID` unset. The API resolves the policy bound to your
key, so nothing in the repository has to know a policy id:

```python
# Resolves via API key → Application → Policy association
result, response, error = client.aiguard.policy_detection.resolve_and_execute_policy(
    content=content,
    direction="IN",
)
```

Configure the association once in the AI Guard Console: create an
Application, associate the API key with it, and assign a Policy to it.

#### Method 2: Explicit policy id

```bash
# .env file
AIGUARD_POLICY_ID=<id>
```

This switches the call to `execute_policy` against that exact id.

> ⚠️ **Only pin an id you have verified exists for your key.** An id the key
> cannot use comes back as `"Policy not found"` **inside an HTTP 200**, with
> no `action` field. Every integration here treats that as no verdict and
> fails closed, so a stale id blocks every request — in a way that reads
> like an outage rather than a typo.

## Comparison: DAS vs Proxy

### DAS (Our Implementation) ✅

**Architecture:**
```
Claude Code (hooks) ─┐
Cursor (future)      ├─→ AI Guard DAS API → Policy Decision
LangChain (future)   ┘
```

**Pros:**
- ✅ No proxy infrastructure
- ✅ Each app independent
- ✅ No single point of failure
- ✅ Works with existing apps
- ✅ Simple deployment (install hooks)
- ✅ Flexible integration (hooks, callbacks, middleware)

**Cons:**
- ⚠️ Each app must integrate
- ⚠️ Requires SDK/API client

### Proxy Mode ❌

**Architecture:**
```
All Apps → AI Guard Proxy → LLM
         (central routing)
```

**Pros:**
- ✅ Centralized control
- ✅ No app code changes (endpoint change only)
- ✅ Uniform policy enforcement

**Cons:**
- ❌ Single point of failure
- ❌ Requires proxy infrastructure
- ❌ All apps must route through proxy
- ❌ More complex to scale
- ❌ Vendor lock-in (proxy endpoint)

## Multi-Scan Flow Example

### Scenario: User asks Claude to fetch a URL

```
User: "Fetch content from https://example.com"
```

**Complete Flow:**

```
SCAN #1: User Input
─────────────────────
[scan_user_input.py]
Content: "Fetch content from https://example.com"
Direction: IN
API Call: execute_policy(...)
Detectors: Toxicity, Injection, PII, Gibberish
Result: ALLOW ✅
Transaction ID: aaa111...

↓ Continue

Claude LLM Decision
───────────────────
Decides to call: WebFetch(url="https://example.com")

↓

SCAN #2: URL Validation
────────────────────────
[scan_url.py]
Content: "https://example.com"
Direction: OUT
API Call: execute_policy(...)
Detectors: Malicious URL, Category Blocking
Result: ALLOW ✅
Transaction ID: bbb222...

↓ Continue

WebFetch Execution
──────────────────
Fetches: https://example.com
Returns: "<html>...</html>"

↓

SCAN #3: Response Validation
─────────────────────────────
[scan_response.py]
Content: "<html>...</html>"
Direction: OUT
API Call: execute_policy(...)
Detectors: PII, Secrets, Malicious Content
Result: ALLOW ✅
Transaction ID: ccc333...

↓ Continue

User sees result: "Here's the content from example.com..."
```

### If Scan #2 Blocks:

```
SCAN #1: ALLOW ✅
    ↓
SCAN #2: BLOCKED ❌
    ↓
❌ WebFetch never executes
❌ Scan #3 never happens
❌ User sees: "Blocked by AI Guard: URL access blocked"
```

## Platform Coverage

The same DAS pattern is applied across every integration; what changes is the
hook point, not the scanning.

| Category | Integrations |
|----------|--------------|
| Agentic IDEs and CLIs | Claude Code, OpenAI Codex CLI, Cursor, Cline, Windsurf |
| API gateways | Google Apigee X, Azure APIM, Kong (Gateway and Konnect) |
| LLM gateways and frameworks | LiteLLM, Portkey, NVIDIA NeMo Guardrails, TrueFoundry |
| Cloud and agent runtimes | AWS Bedrock (SDK hooks and AgentCore), AWS Lambda, Strands Agents |
| CI/CD | GitHub Actions, Jenkins |
| Workflow automation | n8n |

Still planned: LangChain and LlamaIndex callback integrations.

See the [integration index](../README.md#available-integrations) for the
current status of each, which is the authoritative list.

## Security Log Format

All scans are logged to `~/.claude/hooks/aiguard/security.log`:

```
[2026-01-30 15:18:01] Scanning user input: I hate my neighbor...
[2026-01-30 15:18:01] BLOCKED USER INPUT: severity=CRITICAL policy=PolicyRule01 detectors=[toxicity] (txn:abc123...)

[2026-01-30 15:20:00] Scanning URL: https://malicious-site.com
[2026-01-30 15:20:00] BLOCKED URL: https://malicious-site.com severity=HIGH policy=PolicyRule01 detectors=[malicious_url] (txn:def456...)

[2026-01-30 15:22:00] Scanning user input: List my ZPA apps...
[2026-01-30 15:22:00] ALLOWED USER INPUT (txn:ghi789...)
[2026-01-30 15:22:01] MCP REQUEST mcp__zscaler-mcp-server__zpa_list_applications: no significant content to scan (params: {})
[2026-01-30 15:22:02] ALLOWED mcp__zscaler-mcp-server__zpa_list_applications response (txn:jkl012...)
```

### Log Entry Format

```
[timestamp] Event description
[timestamp] ACTION: details policy=policy_id detectors=[list] (txn:transaction_id)
```

## Key Design Decisions

### Why DAS Over Proxy?

1. **Flexibility** - Each AI platform can integrate independently
2. **Resilience** - No single point of failure
3. **Simplicity** - No proxy infrastructure to deploy
4. **Compatibility** - Works with existing applications
5. **Scalability** - Each app scales independently

### Why Hooks Over MCP Server?

1. **AI Guard is not a tool provider** - It's an inspection service
2. **Transparent to AI** - AI agent doesn't need to "know" about security
3. **Automatic enforcement** - Security happens regardless of AI decisions
4. **Platform-specific** - Can optimize for each platform's capabilities

### Why Multiple Scans?

1. **Defense in Depth** - Each layer catches different threats
2. **Fail-Safe** - If one layer misses something, others may catch it
3. **Comprehensive** - Covers prompts, parameters, and responses
4. **Flexibility** - Can enable/disable layers independently

## Summary

This integration implements **Detection as a Service (DAS)** pattern for AI Guard:

- ✅ Stateless API-based inspection
- ✅ Multiple layers of defense
- ✅ Platform-specific hooks
- ✅ No proxy infrastructure
- ✅ Independent application integration
- ✅ Policy-based detection
- ✅ Real-time ALLOW/BLOCK decisions

The implementation provides comprehensive security for AI applications while maintaining flexibility, resilience, and simplicity.

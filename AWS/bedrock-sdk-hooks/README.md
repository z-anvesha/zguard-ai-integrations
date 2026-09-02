# Amazon Bedrock SDK Hooks with Zscaler AI Guard

Registers on the **native interceptor mechanism of the AWS SDK for Python** so that every Amazon Bedrock model invocation made through a protected client is scanned by Zscaler AI Guard -- including calls a framework makes on the application's behalf. A blocked prompt is stopped **before the request is signed or sent**: nothing reaches AWS, nothing is billed.

## Why this seat

A Bedrock guardrail is a **request parameter**: every call site must remember to pass it, and a call without it -- a new code path, a framework internal, a developer shortcut -- is silently unguarded. An SDK interceptor is registered **on the client**: every call through it is scanned, whoever makes it. The two compose; this integration is the safety net under whatever else is configured.

## The implementation

| Language | Directory | SDK | Interception mechanism | Registration |
|----------|-----------|-----|------------------------|--------------|
| Python | [python](./python/) | boto3 / botocore | botocore event system (`before-call` / `after-call`) | per client or per session |

> Python is the only language shipped here. Zscaler publishes an AI Guard client
> for Python; the Go SDK has no AI Guard support and there is no first-party
> Node.js or Java SDK, so those seats would each need a hand-rolled HTTPS client
> and are out of scope for now.

The integration enforces this contract:

- **Prompt leg pre-flight**: the system prompt and every user-role message are scanned before signing; a block means the request never leaves the process
- **Response leg**: scanned before the application sees it; blocked responses withheld or replaced
- **Allowlist content walkers**: each language extracts the text-bearing block shapes it knows -- in the `Converse` dialect `text`, `guardContent` text, `toolUse` name and input, `toolResult` text and JSON, reasoning text, and `searchResult` and citation text; in the type-tagged messages dialect the `system` field plus `text`, `tool_use`, `tool_result` and `thinking` blocks. Cases the SDK cannot express are listed under Limitations in the Python README
- **Unknown shapes fail closed**: documents, images, video, audio, redacted reasoning and any block type a future SDK version adds are marked unscannable; the sole exception is a `cachePoint` marker, which carries no content and is neither extracted nor flagged. Nothing falls off the end unexamined
- **Fail-closed defaults**: missing credentials, unreachable AI Guard, a verdict without an action, and content marked unscannable all block unless explicitly relaxed
- **Two blocking styles**: an exception/error carrying the verdict, or a well-formed `content_filtered` response for callers that cannot be taught a new error type
- **AWS error passthrough**: throttles and auth failures are never masked by a scan verdict
- **Standard env vars** (`AIGUARD_API_KEY`, optional `AIGUARD_CLOUD` / `AIGUARD_POLICY_ID` / `AIGUARD_TIMEOUT`) and the same scan metadata: `transaction_id` per call, `ai_model` stamped from the request's model id, optional session and user attribution

```mermaid
flowchart LR
    subgraph apps["Application processes"]
        PY["Python app<br/>boto3 events"]
    end
    AIGUARD["Zscaler AI Guard<br/>/v1/detection/resolve-and-execute-policy"]
    BR["Amazon Bedrock"]
    PY <-.-> AIGUARD
    PY --> BR
    classDef aiguard fill:#FA582D,stroke:#C93F1A,color:#fff
    class AIGUARD aiguard
```

## Coverage


| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | Every model call through a protected client is scanned pre-flight; a blocked prompt is never signed, sent, or billed |
| Response | ✅ | `Converse` and `InvokeModel` responses are scanned before the application sees them |
| Streaming | ⚠️ | The prompt leg of the streaming operations is scanned exactly as the non-streaming one is; the streamed response itself is not |
| Pre-tool call | ❌ | Tool use rides inside message content at this seat; the agent-loop integrations scan it as first-class `tool_event` payloads |
| Post-tool call | ❌ | Same -- see [bedrock-agentcore](../bedrock-agentcore/) and [strands-agents](../strands-agents/) |

## Getting started

1. Pick your language directory above
2. Copy the single integration file into your project
3. Set the three standard environment variables and run the directory's `scripts/validate` against the live API

## Resources

- [Amazon Bedrock Runtime API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_Operations_Amazon_Bedrock_Runtime.html)
- [the AI Guard Console](https://help.zscaler.com/ai-guard)

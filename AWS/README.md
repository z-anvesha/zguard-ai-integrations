# AWS Integrations for Zscaler AI Guard

Integrations between AWS AI services and **Zscaler AI Guard**.

Each integration is a **single Python file that uses only the standard library**,
plus whatever host it plugs into (`botocore` for the Bedrock hook, the Strands SDK
for the hook provider). There is no `requirements.txt`, no Lambda layer, and
nothing added to your application's dependency tree. The AWS CLI is not required
anywhere, including for the Lambda deployment demo.

## Overview

| Integration | Method | Legs scanned | Use Case |
|-------------|--------|--------------|----------|
| [lambda-decorator](./lambda-decorator/) | Python decorator on the Lambda handler | prompt, response | Prompt/response scanning for **any** Lambda-hosted AI app, regardless of model provider or framework |
| [bedrock-sdk-hooks](./bedrock-sdk-hooks/) | SDK-native interceptor on the Bedrock client (Python) | prompt, response | Scans **every** Bedrock model call an application makes, without changing application code paths |
| [bedrock-agentcore](./bedrock-agentcore/) | A guard called at the four legs of an AgentCore agent loop | prompt, tool input, tool output, response | Full four-leg coverage including tool calls, for agents on Amazon Bedrock AgentCore Runtime |
| [strands-agents](./strands-agents/) | Typed `HookProvider` for the Strands Agents SDK | prompt, tool input, tool output, response | Four-leg coverage via the framework's own hook lifecycle; enforcement shaped by each event's capability boundary |

## Choosing an Integration

The integrations stand at different seats in the stack, and **what each can scan is
what physically passes its seat**:

- **Function boundary** ([lambda-decorator](./lambda-decorator/)) — widest reach, least depth. Works with any event shape and any model, but sees only the prompt entering and the response leaving the function. Agent activity inside the handler is invisible.
- **SDK client** ([bedrock-sdk-hooks](./bedrock-sdk-hooks/)) — sees every model call, including ones your framework makes on your behalf. A Bedrock guardrail is a request parameter someone can forget; an interceptor registered on the client applies to every call through it.
- **Agent loop** ([bedrock-agentcore](./bedrock-agentcore/), [strands-agents](./strands-agents/)) — the only seats that see tool use. Deepest coverage, narrowest fit: they require that specific runtime or framework.

They compose: a decorated Lambda whose handler uses a hooked Bedrock client gets
boundary scanning *and* per-call scanning from two independent seats.

## How scanning maps onto AI Guard

Each leg is one API call. With no policy id configured — the recommended setup —
that call goes to `/v1/detection/resolve-and-execute-policy` and the API resolves
the policy bound to your key. Setting `AIGUARD_POLICY_ID` switches the call to
`/v1/detection/execute-policy` against that exact id.

| Leg | Direction | Seats that have it | What it catches |
|-----|-----------|--------------------|-----------------|
| prompt | `IN` | all four | Prompt injection, secrets and PII heading to the model |
| tool input | `IN` | agentcore, strands | Sensitive data leaving for an external tool |
| tool output | `OUT` | agentcore, strands | Indirect injection and leakage in tool results re-entering the model |
| response | `OUT` | all four | Data loss and unsafe content in what the model produced |

> ⚠️ **Leave `AIGUARD_POLICY_ID` unset unless you have a specific reason.** Most
> users do not know their policy id and do not need it. An id that does not exist
> for your key returns `"Policy not found"` **inside an HTTP 200**, so a typo is
> easy to miss; the integrations fail closed on it rather than reading it as
> permission.

## Enforcement posture

Scanning is **fail-closed** by default: a missing API key, an unreachable API, a
non-HTTPS endpoint, a response carrying no verdict, and any action the integration
does not recognize all block. Each integration accepts `on_error="allow"` as an
explicit opt-out, and `on_unscannable` for content no extractor can read.

Three hardening properties are deliberate and shared by all four:

- **HTTPS is enforced and redirects are refused.** A 3xx would otherwise re-send your API key to whatever host the redirect names.
- **Response reads are bounded by a wall-clock deadline and a size cap.** `urlopen(timeout=)` restarts on every successful read, so a peer that trickles a body could otherwise hold the caller far past its budget.
- **Verdicts are reported exactly as the API returns them.** The integrations enforce the policy's decision and never substitute their own judgement about it.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `AIGUARD_API_KEY` | yes | API key from the AI Guard Console (Private AI Apps > App API Keys) |
| `AIGUARD_CLOUD` | no | Cloud region, defaults to `us1` (us1, us2, eu1, eu2) |
| `AIGUARD_TIMEOUT` | no | Seconds per scan call, defaults to `30` |
| `AIGUARD_POLICY_ID` | no | Pin one policy id — see the warning above |
| `AIGUARD_OVERRIDE_URL` | no | Full base URL, overriding `AIGUARD_CLOUD` |

The integration modules read **real environment variables only** — that is what
Lambda and AgentCore Runtime inject, and it keeps credential handling out of the
scanning code. The interactive runners and `deploy_demo.py` additionally parse a
`.env` in the integration directory as a convenience, so no environment prefix is
needed when testing:

```bash
cp examples/env.example .env      # then add your key
```

`validate.py` does not parse `.env`; source it first, or pass the key inline:

```bash
set -a; source .env; set +a
```

## Testing

Each integration ships a validator and an interactive runner:

```bash
python3 scripts/validate.py     # enforcement paths against the live API
python3 scripts/run_*.py        # interactive: type a prompt, see every leg
```

`validate.py` needs only `AIGUARD_API_KEY`. The runners additionally need AWS
credentials and a Bedrock-enabled region (`AWS_REGION`), because they drive a real
model:

| Integration | Runner | Also needs |
|-------------|--------|------------|
| lambda-decorator | `scripts/run_lambda.py` | `boto3` |
| bedrock-sdk-hooks | `scripts/run_bedrock.py` | `boto3` |
| bedrock-agentcore | `scripts/run_agent.py` | `boto3`, `bedrock-agentcore` |
| strands-agents | `scripts/run_strands.py` | `boto3`, `strands-agents` |

All four runners print the same thing — the legs that fired, then the outcome:

```
> Look up ticket T-1234 and tell me its status

  scan legs
    prompt         ALLOW  severity=CRITICAL  detectors=pii
    tool_input     ALLOW  severity=CRITICAL  detectors=pii
    tool_output    ALLOW
    response       ALLOW

  result   ALLOWED
  answer   The status of ticket T-1234 is open. The customer has asked about refunds.
```

`lambda-decorator` additionally ships the only test that runs on AWS itself:

```bash
python3 scripts/deploy_demo.py     # creates an IAM role + Lambda, invokes twice
python3 scripts/teardown_demo.py   # removes them
```

Both use boto3, create only `aiguardaws-`-prefixed resources, and the teardown
refuses to delete anything else.

## Security Features

These integrations provide protection against:

- Prompt injection, direct and indirect
- Sensitive data exposure (PII, credentials, secrets)
- Malicious URL detection
- Toxic or harmful content
- Malicious code patterns

Which of these actually block is decided by your AI Guard policy, not by the
integration.

## Getting Started

1. Choose the integration whose seat matches your architecture (see above)
2. Copy its single `aiguard_*.py` file into your project
3. Obtain an API key from the AI Guard Console (Private AI Apps > App API Keys)
4. `cp examples/env.example .env` and add the key
5. Run `python3 scripts/validate.py`, then the interactive runner

## IMPORTANT

The contents of this repository are community examples and reference
implementations, supported as best effort by Zscaler. They are intended as
starting points to illustrate integration patterns — review, adapt, and validate
them for your own environment before any production use.

## Resources

- [Zscaler AI Guard](https://www.zscaler.com/products/ai-guard)
- [AI Guard documentation](https://help.zscaler.com/ai-guard)
- [Amazon Bedrock](https://docs.aws.amazon.com/bedrock/)
- [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/)
- [Strands Agents SDK](https://strandsagents.com)

# OpenAI Integrations for Zscaler AI Guard

This directory contains integrations between OpenAI products and **Zscaler AI Guard**.

## Overview

| Integration | Method | Use Case |
|-------------|--------|----------|
| [codex-hooks](./codex-hooks/) | Hooks (automatic) | Runtime protection — scans prompts, bash commands, MCP tool calls, and post-stream final responses |

## Choosing an Integration

### Codex CLI Hooks

**Best for**: Organizations running OpenAI Codex CLI that require always-on, transparent security scanning.

- Automatically scans every user prompt, Bash command, MCP tool input/output, and final assistant response after streaming
- Fail-closed enforcement on prompts and tool calls — nothing reaches the model or executes when a scan cannot be completed
- Pure Python via [`zscaler-sdk-python`](https://github.com/zscaler/zscaler-sdk-python); no `curl` or `jq` dependency
- Drop-in `.codex/` directory; works at project or global scope

[View Codex CLI Hooks Integration](./codex-hooks/)

## Security Features

The Codex CLI hooks integration provides protection against:

- **Prompt injection** — direct, and indirect injection carried in MCP tool output
- **Sensitive data loss** — secrets, credentials, and PII in prompts, command output, and responses
- **Malicious commands** — destructive or exfiltrating shell commands, blocked before execution
- **Unsafe content** — toxicity and policy-violating material in either direction

All scanning runs through the AI Guard policy detection API
(`resolve-and-execute-policy`), so detection categories and enforcement actions are
controlled centrally by your AI Guard policy rather than by the hook code.

## Requirements

- [Codex CLI](https://github.com/openai/codex) — the `hooks` feature is stable and on by default in current versions
- Python 3.8+
- `zscaler-sdk-python` **>= 1.9.44**
- Zscaler AI Guard API key

## IMPORTANT

The contents of this repository are community examples and reference
implementations. They are intended as starting points to illustrate integration
patterns — review, adapt, and validate them for your own environment before any
production use.

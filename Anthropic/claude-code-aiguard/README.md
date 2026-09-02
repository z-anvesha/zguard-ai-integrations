# Zscaler AI Guard Integration for Claude Code

Runtime security hooks for Claude Code that scan prompts, MCP tool calls, and responses through Zscaler AI Guard before execution.

## Overview

This integration provides transparent security scanning for Claude Code interactions:

- **User Input Scanning** (`scan_user_input.py`, IN) - Scans prompts before they reach Claude LLM
- **MCP Tool Call Scanning** (`scan_mcp_request.py`, IN) - Scans tool parameters before calling MCP servers
- **Response Scanning** (`scan_response.py`, OUT) - Scans tool responses before returning to user
- **URL Scanning** (`scan_url.py`, OUT) - Scans URLs before web requests
- **File Read Scanning** (`scan_file_read.py`, IN) - Scans sensitive files before Claude reads them; ships with the integration but is **not** enabled by the bundled `settings.json` (see below)

Hooks signal a block two different ways, depending on the Claude Code event contract:
`scan_user_input.py` exits **2**, while the `PreToolUse`/`PostToolUse` hooks exit **0**
and emit `{"continue": false, ...}` on stdout. Both are normal — when testing by hand,
check stdout, not just the exit code.

## Architecture

```
User Input
  ↓
[AIGuard Hook] → Scan → ALLOW/BLOCK
  ↓
Claude LLM
  ↓
MCP Tool Call (e.g., zscaler_list_devices)
  ↓
[AIGuard Hook] → Scan → ALLOW/BLOCK
  ↓
MCP Server (Docker) → Executes Tool
  ↓
Tool Response
  ↓
[AIGuard Hook] → Scan → ALLOW/BLOCK
  ↓
User sees result
```

## Prerequisites

- **Claude Code** CLI installed
- **Python 3.8+** with `zscaler-sdk-python` **1.9.44 or newer**
- **Zscaler AI Guard** account with:
  - API Key
  - Cloud environment (us1, us2, eu1, eu2)
  - Policy configured and activated

> **Why 1.9.44+:** releases up to 1.9.42 never attached the Bearer token to AI Guard
> policy-detection calls (the legacy dispatch branch was missing in
> `oneapi_http_client.send_request`), so every scan failed with
> `401 Unauthorized - token refresh attempts exhausted or OAuth not available`.
> The hooks rely on the fix and no longer carry a workaround.

## Installation

### 1. Install Dependencies

```bash
pip install 'zscaler-sdk-python>=1.9.44'
```

The hooks use the public entry point `LegacyAIGuardClient`, reached as
`client.aiguard.policy_detection`:

```python
from zscaler.oneapi_client import LegacyAIGuardClient

with LegacyAIGuardClient({"api_key": key, "cloud": "us1", "timeout": 30}) as client:
    result, _, error = client.aiguard.policy_detection.resolve_and_execute_policy(
        content="text to scan", direction="IN",
    )
```

There is no `LegacyZGuardClient` class and no `zscaler.zaiguard` module — those were
pre-release names. `client.zguard` still works as a deprecated alias for `client.aiguard`.

### 2. Configure Environment Variables

Choose one of the following methods:

#### Option A: Using .env File (Recommended)

```bash
# Copy the example file
cp .env.example .env

# Edit with your credentials
nano .env
```

Add your credentials:

```bash
# Required
AIGUARD_API_KEY=your_api_key_here
AIGUARD_CLOUD=us1

# Optional
# AIGUARD_POLICY_ID=   # leave unset: the API auto-resolves
AIGUARD_TIMEOUT=30
```

**Then copy to Claude Code hooks directory:**

```bash
mkdir -p ~/.claude/hooks/aiguard
cp .env ~/.claude/hooks/aiguard/.env
```

#### Option B: System Environment Variables

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
export AIGUARD_API_KEY="your_api_key_here"
export AIGUARD_CLOUD="us1"
# export AIGUARD_POLICY_ID="<id>"   # rarely needed; unset = auto-resolve
export AIGUARD_TIMEOUT="30"     # Optional
```

Then reload:

```bash
source ~/.zshrc  # or source ~/.bashrc
```

### 3. Install Hook Scripts

```bash
# Copy all hook scripts to Claude Code directory
mkdir -p ~/.claude/hooks/aiguard
cp hooks/*.py ~/.claude/hooks/aiguard/
chmod +x ~/.claude/hooks/aiguard/*.py
```

### 4. Configure Claude Code Hooks

`~/.claude/settings.json` usually holds unrelated settings (enabled plugins, model
preferences, notification options). **Merge** the `hooks` key into it — do not copy
this file over the top, which would discard everything else:

```bash
python3 -c "import json,os,shutil; d=os.path.expanduser('~/.claude/settings.json'); shutil.copy(d,d+'.backup'); c=json.load(open(d)); c['hooks']=json.load(open('settings.json'))['hooks']; json.dump(c,open(d,'w'),indent=2); print('merged; backup at',d+'.backup')"
```

Or manually add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
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
            "type": "command",
            "command": "python3 ~/.claude/hooks/aiguard/scan_url.py"
          }
        ]
      },
      {
        "matcher": "mcp__.*",
        "hooks": [
          {
            "type": "command",
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
            "type": "command",
            "command": "python3 ~/.claude/hooks/aiguard/scan_response.py"
          }
        ]
      }
    ]
  }
}
```

## AI Guard Configuration

### Get API Key

1. Log in to **AI Guard Console**
2. Navigate to **Private AI Apps** → **App API Keys**
3. Create or copy your API key

### Configure Policy

1. Go to **Policies** in AI Guard Console
2. Create or edit a policy
3. Configure detectors:
   - **Prompt Detectors**: Toxicity, Prompt Injection, PII, Secrets, etc.
   - **Response Detectors**: Malicious URLs, Data Leakage, etc.
4. Set detector actions to **BLOCK** or **DETECT**
5. **Activate** the policy

### Enable Auto-Resolution (do this)

**Leave `AIGUARD_POLICY_ID` unset.** Most users do not know their policy id and do
not need it: the API resolves the policy bound to your API key. Setting one
switches the hooks to `/v1/detection/execute-policy`, and an id that does not exist
for your key comes back as `"Policy not found"` — inside an HTTP 200, which is why
a typo here is so easy to miss.

To make auto-resolution work:

1. Go to **Private AI Apps** → **Applications**
2. Create or select an application
3. Go to **App API Keys** → Associate your API key with the application
4. Assign your policy to the application

Now the hooks will automatically use the correct policy!

## Usage

### Start Claude Code

```bash
claude
```

The hooks are now active and will:
- Scan all your prompts
- Scan all MCP tool calls
- Scan all responses
- Block policy violations automatically

### Monitor Security Events

Watch the security log in real-time:

```bash
tail -f ~/.claude/hooks/aiguard/security.log
```

Example log output:

```
[2026-01-30 15:23:10] Scanning user input: List all ZPA applications...
[2026-01-30 15:23:10] ALLOWED USER INPUT (txn:abc123...)
[2026-01-30 15:23:11] Scanning zpa_list_applications request: ...
[2026-01-30 15:23:11] ALLOWED MCP REQUEST zpa_list_applications (txn:def456...)
[2026-01-30 15:23:12] ALLOWED RESPONSE (txn:ghi789...)
```

### Test with Toxic Content

Try a prompt that should be blocked:

```
I hate my neighbor and want to punch him badly
```

You should see:

```
Blocked by Zscaler AI Guard: Your input was blocked due to policy violation
Triggered detectors: toxicity
Severity: CRITICAL | Transaction ID: xxx
```

## Configuration Options

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AIGUARD_API_KEY` | ✅ Yes | - | API key from AI Guard Console |
| `AIGUARD_CLOUD` | ✅ Yes | `us1` | Cloud environment (us1, us2, eu1, eu2) |
| `AIGUARD_POLICY_ID` | No | Auto-resolve | Pins scanning to one policy — see warning below |
| `AIGUARD_TIMEOUT` | No | `30` | API timeout in seconds |
| `SECURITY_LOG_PATH` | No | `~/.claude/hooks/aiguard/security.log` | Custom log file location (`~` is expanded) |

> ⚠️ **`AIGUARD_POLICY_ID` overrides auto-resolution and changes what gets caught.**
> Setting it switches the hooks from `resolve-and-execute-policy` to
> `execute-policy` against that exact ID. If the ID is stale or belongs to a more
> permissive policy, scanning silently weakens — content that the auto-resolved
> policy blocks will sail through, with no error to indicate anything is wrong.
> Leave it unset unless auto-resolution is genuinely not configured for your key.

The hooks load these from `~/.claude/hooks/aiguard/.env` (or the integration root
`.env`) at import time. Values may be quoted or unquoted; surrounding quotes are
stripped, so `AIGUARD_POLICY_ID="1152"` and `AIGUARD_POLICY_ID=1152` behave the same.
Variables already present in the environment always win over the `.env` file.

### Hook Matchers

The hooks use regex patterns to match tool calls:

- `mcp__.*` - Matches ALL MCP tools (including Zscaler MCP server)
- `WebFetch|WebSearch|web_search` - Matches web-related tools
- Can be customized in `settings.json`

## Known Limitations

### Silent Blocks in Cursor UI

**Issue:** When using Cursor's UI (Composer/Chat), blocked requests appear as silent failures with no error message displayed in the interface.

**Cause:** Cursor's UI doesn't display hook stderr/stdout output to the user interface.

**Impact:**
- ✅ Security **works correctly** - blocks happen and are logged
- ❌ UX is poor - users don't see why they were blocked
- Users may think Claude Code is frozen or broken

**Workarounds:**

1. **Use Claude Code CLI** (error messages display properly):
   ```bash
   claude
   ```
   Example output when blocked:
   ```
   Operation stopped by hook: Zscaler AI Guard blocked your input
   ```

2. **Monitor security logs** to see block reasons:
   ```bash
   # Watch logs in real-time
   tail -f ~/.claude/hooks/aiguard/security.log
   
   # Check last 5 blocks
   tail -20 ~/.claude/hooks/aiguard/security.log | grep BLOCKED
   ```
   
   Example log entry:
   ```
   [2026-02-03 21:47:37] BLOCKED USER INPUT: severity=CRITICAL policy=policy_760 
   detectors=[credentials] (txn:405b4456-75cb-41e8-a1f8-2a0703f3f092)
   ```

3. **Enable desktop notifications** (optional - see `UI_SILENT_BLOCK_LIMITATION.md` for setup)

**When to worry:** If you see no response in Cursor UI, check logs to confirm it's a security block and not a system issue.

## Troubleshooting

### Hooks Not Running

1. Check Claude Code settings are loaded:
   ```bash
   cat ~/.claude/settings.json
   ```

2. Verify scripts are executable:
   ```bash
   ls -la ~/.claude/hooks/aiguard/
   ```

3. Test manually:
   ```bash
   echo '{"prompt":"test"}' | python3 ~/.claude/hooks/aiguard/scan_user_input.py; echo "exit=$?"
   ```
   Exit `0` = allowed, `2` = blocked. An `ImportError` naming `LegacyZGuardClient`
   means the installed copy under `~/.claude/hooks/aiguard/` is stale — recopy the
   hooks from this directory (installation step 3).

4. Check the tool hooks, which block via stdout rather than exit code:
   ```bash
   echo '{"tool_name":"mcp__x__y","tool_input":{"body":"test"}}' | python3 ~/.claude/hooks/aiguard/scan_mcp_request.py
   ```
   A block prints a JSON object containing `"continue": false`.

### API Key Not Found

Error: `AIGUARD_API_KEY environment variable not set`

**Solution**: Ensure environment variables are set correctly:

```bash
# Check if variables are set
env | grep AIGUARD

# If using .env file, ensure it's in the right location
ls -la ~/.claude/hooks/aiguard/.env

# If using shell profile, reload it
source ~/.zshrc
```

### Policy Not Found

Error: `Policy: None` in logs

**Solution**: Either:
1. Associate the API key with an application and policy so auto-resolution works (preferred), OR
2. Configure API Key → Application → Policy association in AI Guard Console

### Content Not Being Blocked

1. Verify detector is enabled and set to **BLOCK** (not DETECT)
2. Check policy is **activated**
3. **Unset `AIGUARD_POLICY_ID`** and retest — a stale ID silently pins scanning to
   the wrong policy (see the warning in Configuration Options)
4. **Check the direction.** A policy can allow `OUT` while blocking `IN`. Prompt,
   MCP-request, and file-read scanning use `direction=IN`; URL and response
   scanning use `direction=OUT`. If only some hooks appear to block, compare both:

   ```bash
   python3 ../claude-code-skill/scripts/scan.py --type prompt   --content "test phrase"
   python3 ../claude-code-skill/scripts/scan.py --type response --content "test phrase"
   ```
5. Check security log for the actual response from AI Guard

### Everything Is Blocked (including "hello")

If ordinary prompts are blocked with **`0 detectors triggered`** and a severity but
no detector names, the policy itself is denying unconditionally — the hooks are
working and faithfully reporting the API verdict. Confirm independently:

```bash
python3 -c "
import os
from zscaler.oneapi_client import LegacyAIGuardClient
with LegacyAIGuardClient({'api_key': os.environ['AIGUARD_API_KEY'], 'cloud': os.environ.get('AIGUARD_CLOUD','us1')}) as c:
    r, _, e = c.aiguard.policy_detection.resolve_and_execute_policy(content='hello', direction='IN')
    print(r.action, r.severity, r.policy_name, sum(1 for d in r.detector_responses.values() if d.triggered), 'triggered')
"
```

If that prints `BLOCK` for `hello`, fix the rule in the AI Guard Console so it
blocks on detector hits rather than by default. **Do not register the
`UserPromptSubmit` hook until this is resolved** — every prompt you type will be
blocked and Claude Code becomes unusable.

### Nothing Appears in the Security Log

Older versions used `SECURITY_LOG_PATH` verbatim, so a value starting with `~`
created a directory literally named `~` in whatever directory Claude Code was
launched from, hiding every log line there. The path is now expanded properly. If
you have a stray `~` directory from an earlier install, delete it:

```bash
find . -maxdepth 1 -name '~' -type d
```

## Security Considerations

### Fail-Closed Behavior

The hooks **fail closed**: anything that prevents a verdict blocks the action
rather than allowing it.

| Situation | Outcome |
|-----------|---------|
| `ALLOW` | allowed |
| `DETECT` | allowed — monitor-only: reported and logged, not enforced |
| `BLOCK` | blocked |
| `AIGUARD_API_KEY` not set | blocked |
| AI Guard API unreachable, or a network error | blocked |
| HTTP 401/403 (bad or revoked key) | blocked |
| HTTP 200 carrying no `action` | blocked |
| Any unrecognised verdict | blocked |

The last two matter most, because they look like success. A verdict-less 200 is
the shape a soft failure takes — `"Policy not found"` when `AIGUARD_POLICY_ID`
names a policy your key cannot use — and reading it as permission silently
disables scanning while the hooks appear healthy.

Every block names its cause, so a configuration problem is distinguishable from
a content decision:

```
🛑 BLOCKED BY ZSCALER AI GUARD
Zscaler AI Guard is not configured (AIGUARD_API_KEY is not set),
so your prompt could not be scanned.
```

**This is a deliberate trade-off:** if AI Guard is unreachable, Claude Code stops
until it is reachable again. If you would rather keep working during an outage,
unhook the scanners (comment them out of `settings.json`) instead of weakening
them — a hook that allows whatever it cannot scan provides no protection while
still looking like it does.

### API Key Protection

- **Never commit** `.env` files to version control
- Use `.env.example` as a template
- Rotate API keys regularly
- Use least-privilege API keys when possible

### Log File Security

Security logs contain request/response samples. Ensure:
- Logs are in a protected directory (`~/.claude/hooks/aiguard/`)
- Log rotation is configured for production use
- Sensitive data is masked if needed

## File Structure

```
~/.claude/
├── settings.json                # Hook configuration (merge, never overwrite)
└── hooks/
    └── aiguard/
        ├── .env                 # Your credentials (not in repo)
        ├── load_env.py          # Environment variable loader
        ├── aiguard_utils.py     # Shared client/config/logging helpers
        ├── notification_helper.py # Optional desktop notifications
        ├── scan_user_input.py   # User prompt scanner        (IN)
        ├── scan_mcp_request.py  # MCP tool call scanner      (IN)
        ├── scan_file_read.py    # Sensitive file scanner     (IN, opt-in)
        ├── scan_url.py          # URL scanner                (OUT)
        ├── scan_response.py     # Response scanner           (OUT)
        └── security.log         # Security event log
```

### Optional: enable file-read scanning

`scan_file_read.py` is not wired up by the bundled `settings.json`. To scan
sensitive files (`.env`, `.pem`, SSH keys, credentials) before Claude reads them,
add this entry to the `PreToolUse` array:

```json
{
  "matcher": "Read",
  "hooks": [
    {
      "type": "command",
      "command": "python3 ~/.claude/hooks/aiguard/scan_file_read.py"
    }
  ]
}
```

It only scans paths matching its sensitive-file patterns; everything else is
allowed without an API call.

## Support

For issues with:
- **AI Guard API**: Contact Zscaler Support
- **Claude Code**: Check Anthropic documentation
- **This Integration**: File an issue in the repository

## License

See LICENSE file in repository root.

# Jenkins — Zscaler AI Guard Policy Validation

This integration adds **Zscaler AI Guard** policy validation to a Jenkins Declarative Pipeline. When monitored files change, the pipeline runs `scripts/scan_policy.py` against `config/test-prompts.yaml` using `zscaler-sdk-python` (`LegacyAIGuardClient`) — the same API as the [GitHub Actions](../../github-actions/) integration (`resolve-and-execute-policy` / optional `execute-policy`).

The included **Deploy Model to Vertex AI** and **Test Model Endpoint** stages are optional examples (same pattern as before); use **SKIP_DEPLOY** or run only on branches without `main` if you do not use GCP.

---

## Coverage

| Phase | Description |
|-------|-------------|
| Policy validation (IN / OUT) | Synthetic prompts/responses in `config/test-prompts.yaml` |
| CI gate | Non-zero exit if any **required** test mismatches; `optional: true` → **WARN** only |
| Vertex deploy | Example only — requires GCP credentials |

> For detector categories, see [Zscaler AI Guard](https://help.zscaler.com/ai-guard).

---

## Prerequisites

- Jenkins 2.400+ with [Pipeline](https://plugins.jenkins.io/workflow-aggregator/)
- Python 3.11+ on the agent
- For Vertex stages: `gcloud` CLI on the agent
- Zscaler AI Guard API key

---

## Jenkins credentials

| Credential ID | Type | Required for scan | Description |
|---------------|------|:-----------------:|-------------|
| `aiguard-api-key` | Secret text | Yes | AI Guard Bearer token (`AIGUARD_API_KEY`) |

**Optional cloud / policy ID** are passed as **build parameters** (`AIGUARD_CLOUD`, `AIGUARD_POLICY_ID`) so you do not need extra credentials for defaults. To bind them as Secret text instead, add `withCredentials` entries and `export` them in the scan stage (same variable names).

Vertex example (deploy / test only):

| Credential ID | Type |
|-----------------|------|
| `gcp-sa-key` | Secret file (JSON) |
| `gcp-project-id` | Secret text |
| `gcp-region` | Secret text |
| `hf-token` | Secret text |

If you rename credential IDs, update the `Jenkinsfile` accordingly.

**Do not** create `AIGUARD_CLOUD` as an empty Jenkins secret — empty values are treated as unset and default to `us1` in `scan_policy.py`, but avoid blank secrets for clarity.

---

## Monitored paths (triggers scan stage)

The **Detect Changes** stage sets `SCAN_NEEDED` when the latest changeset touches any of:

- `config/model-config.yaml`
- `config/test-prompts.yaml`
- `scripts/scan_policy.py`
- `Jenkinsfile`

Use **Build with Parameters** → **FORCE_RUN** for the first run or when SCM polling does not see a diff.

---

## Test suite

Edit **`config/test-prompts.yaml`**:

- `expected_action`: `ALLOW`, `BLOCK`, `DETECT`, or a list (e.g. `[BLOCK, DETECT]`)
- `optional: true`: mismatch logs **WARN**; build still succeeds
- `settings.scan_enabled: false`: scanner exits 0 immediately

See [github-actions/README.md](../../github-actions/README.md) for full semantics, PII false-positive notes, and log field meanings (**Triggered** vs **Blocking**).

---

## Local run

From this directory:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export AIGUARD_API_KEY="your-key"
export AIGUARD_CLOUD=us1   # optional
python scripts/scan_policy.py --config config/test-prompts.yaml
```

The scan stage needs no GCP access at all — it only calls the AI Guard API.

### Model deploy and teardown

The deploy and undeploy scripts drive `gcloud` (Model Garden's EULA acceptance
and Hugging Face token flags have no `google-cloud-aiplatform` equivalent), so
they need an authenticated `gcloud` rather than the AI Guard key. Both accept
`--dry-run`, which prints the exact commands without creating or deleting
anything:

```bash
export GCP_PROJECT_ID="your-project"
export GCP_REGION="us-central1"        # optional; defaults to deployment.region
python scripts/deploy_model.py --dry-run
```

> ⚠️ **A real deploy starts GPU-backed infrastructure and bills for it until you
> tear it down.** The pipeline never undeploys, so nothing stops the meter on its
> own:
>
> ```bash
> python scripts/undeploy_model.py
> ```
>
> It matches the endpoint display name **exactly**, exits 0 when there is nothing
> to remove, and undeploys every model before deleting the endpoint — Vertex
> refuses to delete an endpoint that still has one attached.

---

## Repository layout

```
declarative-pipeline/
├── Jenkinsfile
├── config/
│   ├── model-config.yaml    # Vertex model — triggers pipeline when changed
│   └── test-prompts.yaml    # AI Guard policy test cases
├── scripts/
│   ├── scan_policy.py        # AI Guard validation (zscaler-sdk-python)
│   ├── deploy_model.py       # deploy from Model Garden (--dry-run supported)
│   ├── test_model.py
│   ├── undeploy_model.py     # tear down the endpoint to stop GPU costs
│   └── vertex_common.py      # shared gcloud helpers
├── requirements.txt
├── .env.example
└── README.md
```

Point your Jenkins job **workspace root** at `declarative-pipeline` (or the repo root that contains these paths with the same relative layout).

---

## Troubleshooting

| Issue | What to do |
|-------|------------|
| `aiguard-api-key` not found | Create the Secret text credential with that ID, or change `credentialsId` in the Jenkinsfile |
| Scan stage skipped | Use **FORCE_RUN**, or push a change under a monitored path |
| `api..zseclipse.net` / parse error | Empty cloud — set **AIGUARD_CLOUD** parameter to `us1` (or your region) |
| Benign tests WARN with BLOCK / PII | Expected on strict tenants; tune AI Guard or keep `optional: true` |
| Deploy fails | Optional stage — use **SKIP_DEPLOY** or fix GCP / `hf-token` |

---

## References

- [Zscaler AI Guard](https://help.zscaler.com/ai-guard)
- [zscaler-sdk-python](https://github.com/zscaler/zscaler-sdk-python)
- [Jenkins Pipeline](https://www.jenkins.io/doc/book/pipeline/)

The scanner and tests are aligned with this repo's GitHub Actions integration.

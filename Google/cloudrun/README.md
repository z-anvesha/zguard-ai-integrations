# Google Cloud Run — AI Guard on Apigee provisioning pipelines

Git-push-driven, **Cloud Build → Cloud Run Job** automation that provisions the
Zscaler AI Guard + Vertex AI on Apigee X reference patterns end to end: enable
APIs, create the Vertex service account and IAM bindings, configure the encrypted
KVM, and import + deploy the Apigee bundles. The sibling [`../apigee`](../apigee)
folder holds the **manual** bundles; this folder automates deploying them with no
hand-run `gcloud` or `curl` steps.

Two self-contained pipelines — use whichever fits:

| Folder | Pattern | Best for |
|--------|---------|----------|
| [`flow/`](flow) | **SharedFlow** — reusable `ZSCALER-AIGUARD` flow + thin `vertex-aiguard-sync` proxy | Many proxies sharing one AI Guard posture |
| [`proxy/`](proxy) | **Monolithic** — self-contained `vertex-aiguard` proxy with the policies inline | A single LLM proxy; simplest footprint |

Both scan the prompt on the way in and the response on the way out — a blocked
prompt never reaches Vertex — and call Vertex as a dedicated service account with
the Apigee `tokenCreator` binding wired automatically. They differ in how a block
is returned: `flow/` answers in the caller's own dialect at HTTP 200 so an SDK
client parses the refusal, while `proxy/` returns a JSON error at HTTP 403.

| | `flow/` | `proxy/` |
|---|---|---|
| Basepath | `/vertex-aiguard-sync` + full Vertex path | `/vertex`, bare Gemini body |
| Block | caller's dialect, HTTP 200 | JSON error, HTTP 403 |
| Dialects | Gemini, OpenAI, Anthropic, MCP, SSE | Gemini |

## Everything is Python

`provision.py`, `setup/bootstrap.py` and `setup/provision_org.py` use only the
standard library plus the `gcloud` already in the base image. There is no `jq`,
no `zip`, and no pip install — bundle packaging and management-API calls are done
in Python, which also keeps the provisioner image to a bare
`google/cloud-sdk:slim`.

## Self-contained by design

Each pipeline carries its **own copy** of the Apigee bundles under `bundles/`,
rather than referencing the canonical ones in [`../apigee`](../apigee):

- `flow/bundles/` ↔ `../apigee/sharedflow/` (`ZSCALER-AIGUARD`, `vertex-aiguard-sync`)
- `proxy/bundles/vertex-aiguard/` ↔ `../apigee/apiproxy/`

This is deliberate: it keeps each pipeline a complete clone-and-run unit and lets
the Docker build context be the pipeline folder alone. The trade-off is that each
bundle exists in two places — when you change a canonical bundle in
[`../apigee`](../apigee), update the matching copy here. Each pipeline's README
carries the exact copy commands.

## Prerequisites

An Apigee X org, an AI Guard API key, and an account with Owner (or equivalent)
on the GCP project to run the one-time bootstrap. The Vertex service account and
its IAM bindings are created by the pipeline.

**No Apigee org yet?** The pipelines configure an org; they do not create one.
`flow/setup/provision_org.py` does that part — org, runtime instance,
environment, environment group and both attachments:

```bash
python3 flow/setup/provision_org.py --project=YOUR_PROJECT_ID --region=us-west1
```

An evaluation org is free and expires after 60 days. Two things that bite:

- **The region must match any existing API Hub instance in the project.** A
  mismatch is rejected with *"an API Hub instance already exists in location X"*.
- **The runtime instance takes 20–40 minutes**, and it is visible with
  `state: CREATING` long before it is usable. Attaching an environment to an
  instance that is still creating fails with *"the resource is locked by another
  operation"*. `provision_org.py` waits for `ACTIVE`; every step re-checks before
  creating, so an interrupted run resumes rather than duplicating.

## Quick start

```bash
cd flow      # or: cd proxy
cat README.md
python3 setup/bootstrap.py --project=YOUR_PROJECT_ID --region=us-west1 --apigee-env=eval
```

Each pipeline gets its own Cloud Build trigger pointed at that folder's
`cloudbuild.yaml` (e.g. `--build-config=Google/cloudrun/flow/cloudbuild.yaml`).
The GitHub-App connection is 1st-gen, so triggers are created with
`--region=global` while resources deploy to `_REGION`. See each folder's README
for the full bootstrap → trigger → push flow.

## Enforcement posture

Fail-closed by default. A missing API key, an unreachable API, a non-200 from the
scan callout, a response carrying no action, and any verdict the flow does not
recognise all block. `failOpen=true` on the proxy is the explicit opt-out, and
`DETECT` is AI Guard's monitor-only verdict: reported, not enforced.

> ⚠️ **Leave `_AIGUARD_POLICY_ID` empty.** Empty means the API resolves the policy
> bound to your key. A policy id that does not exist for the key comes back as
> `"Policy not found"` **inside an HTTP 200** — the pipelines treat that as no
> verdict and fail closed, but it is a confusing way to discover a typo.

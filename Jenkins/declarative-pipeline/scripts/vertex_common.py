#!/usr/bin/env python3
"""
Shared helpers for the Vertex AI model deploy/undeploy scripts.

Both scripts drive `gcloud` rather than google-cloud-aiplatform: deploying from
Model Garden needs the EULA acceptance and Hugging Face token flags that only
the CLI exposes. This mirrors the pattern used by the Google integration's
provisioning scripts.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG = "config/model-config.yaml"
#: Endpoints created by this pipeline get this suffix on the model display name.
ENDPOINT_SUFFIX = "-secure"


def die(msg: str) -> "None":
    print("\nERROR: %s" % msg, file=sys.stderr, flush=True)
    sys.exit(1)


def load_config(path: str) -> dict[str, Any]:
    cfg_path = Path(path)
    if not cfg_path.is_file():
        die("config file not found: %s" % path)
    try:
        cfg = yaml.safe_load(cfg_path.read_text())
    except yaml.YAMLError as exc:
        die("could not parse %s: %s" % (path, exc))
    if not isinstance(cfg, dict):
        die("%s did not parse to a mapping" % path)
    return cfg


def require(cfg: dict[str, Any], *keys: str) -> Any:
    """Fetch a nested config value, naming the full path if it is missing."""
    node: Any = cfg
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            die("%s is missing '%s'" % (DEFAULT_CONFIG, ".".join(keys)))
        node = node[key]
    return node


def endpoint_display_name(cfg: dict[str, Any]) -> str:
    return "%s%s" % (require(cfg, "model", "display_name"), ENDPOINT_SUFFIX)


def gcloud(*args: str, check: bool = True, dry_run: bool = False) -> str:
    """Run gcloud and return stdout. Errors carry stderr so failures are readable."""
    cmd = ["gcloud"] + [str(a) for a in args]
    if dry_run:
        print("    [dry-run] %s" % " ".join(cmd), flush=True)
        return ""
    if not shutil.which("gcloud"):
        die("gcloud is not on PATH")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        die("%s failed:\n%s" % (" ".join(cmd), (proc.stderr or proc.stdout or "").strip()))
    return (proc.stdout or "").strip()


def split_ids(raw: str) -> list[str]:
    """Split a gcloud --format=value(...) result into ids.

    gcloud separates a repeated field's values with tabs on a single line and
    separate resources with newlines, so splitting on generic whitespace is the
    only form that handles both. Trailing path segments are stripped, since
    `value(name)` yields a full resource path for endpoints.
    """
    return [chunk.rsplit("/", 1)[-1] for chunk in raw.split() if chunk]


def list_endpoint_ids(project: str, region: str, display_name: str,
                      dry_run: bool = False) -> list[str]:
    """Endpoint ids whose display name matches exactly.

    The filter is an equality match, not gcloud's `~` regex operator: these ids
    are fed to a delete, and a regex would also match any endpoint whose name
    merely contains this one.
    """
    raw = gcloud("ai", "endpoints", "list",
                 "--project", project,
                 "--region", region,
                 "--filter", "displayName=%s" % display_name,
                 "--format", "value(name)", dry_run=dry_run)
    return split_ids(raw)


def deployed_model_ids(endpoint_id: str, project: str, region: str,
                       dry_run: bool = False) -> list[str]:
    raw = gcloud("ai", "endpoints", "describe", endpoint_id,
                 "--project", project,
                 "--region", region,
                 "--format", "value(deployedModels.id)",
                 check=False, dry_run=dry_run)
    return split_ids(raw)


def delete_endpoint(endpoint_id: str, project: str, region: str,
                    dry_run: bool = False) -> None:
    """Undeploy every model on an endpoint, then delete it.

    Vertex refuses to delete an endpoint that still has a model deployed, so the
    undeploy loop is a precondition, not tidiness.
    """
    for model_id in deployed_model_ids(endpoint_id, project, region, dry_run):
        print("    undeploying model %s" % model_id, flush=True)
        gcloud("ai", "endpoints", "undeploy-model", endpoint_id,
               "--project", project,
               "--region", region,
               "--deployed-model-id", model_id,
               "--quiet", dry_run=dry_run)

    print("    deleting endpoint %s" % endpoint_id, flush=True)
    gcloud("ai", "endpoints", "delete", endpoint_id,
           "--project", project,
           "--region", region,
           "--quiet", dry_run=dry_run)

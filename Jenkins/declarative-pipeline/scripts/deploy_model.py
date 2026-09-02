#!/usr/bin/env python3
"""
Deploy a model from Vertex AI Model Garden to a Vertex AI endpoint.

Reads configuration from config/model-config.yaml. Any endpoint already carrying
the target display name is undeployed and deleted first, so a re-run replaces the
deployment rather than accumulating duplicates.

    python scripts/deploy_model.py
    python scripts/deploy_model.py --dry-run          # print the gcloud calls only
    python scripts/deploy_model.py --config other.yaml

Environment:
    GCP_PROJECT_ID   required
    GCP_REGION       optional; falls back to deployment.region in the config
    HF_TOKEN         optional; required for gated Hugging Face models
    CONFIG_FILE      optional; same as --config

This deploys GPU-backed infrastructure and starts incurring cost. Use
scripts/undeploy_model.py to tear it back down.
"""

from __future__ import annotations

import argparse
import os
import sys

from vertex_common import (
    DEFAULT_CONFIG,
    delete_endpoint,
    die,
    endpoint_display_name,
    gcloud,
    list_endpoint_ids,
    load_config,
    require,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=os.environ.get("CONFIG_FILE", DEFAULT_CONFIG),
                        help="path to model-config.yaml (default: %s)" % DEFAULT_CONFIG)
    parser.add_argument("--dry-run", action="store_true",
                        help="print the gcloud commands without running them")
    args = parser.parse_args()

    cfg = load_config(args.config)

    project = os.environ.get("GCP_PROJECT_ID", "").strip()
    if not project:
        die("GCP_PROJECT_ID environment variable is required")

    # The env var wins so the pipeline can target a region per branch; the
    # config value is the documented default.
    region = (os.environ.get("GCP_REGION", "").strip()
              or cfg.get("deployment", {}).get("region", "")
              or "us-central1")

    model_id = require(cfg, "model", "huggingface_id")
    machine_type = require(cfg, "deployment", "machine_type")
    accel_type = require(cfg, "deployment", "accelerator_type")
    accel_count = require(cfg, "deployment", "accelerator_count")
    display_name = endpoint_display_name(cfg)

    print("=" * 60)
    print("  Deploying Model to Vertex AI")
    print("=" * 60)
    print("  Model:         %s" % model_id)
    print("  Display Name:  %s" % display_name)
    print("  Machine Type:  %s" % machine_type)
    print("  Accelerator:   %s x %s" % (accel_type, accel_count))
    print("  Region:        %s" % region)
    print("  Project:       %s" % project)
    if args.dry_run:
        print("  Mode:          DRY RUN — no resources will be created")
    print("=" * 60, flush=True)

    existing = list_endpoint_ids(project, region, display_name, args.dry_run)
    if existing:
        print("\n==> Replacing %d existing endpoint(s) with this display name"
              % len(existing), flush=True)
        for endpoint_id in existing:
            delete_endpoint(endpoint_id, project, region, args.dry_run)
        print("    cleanup complete", flush=True)

    print("\n==> Deploying from Model Garden", flush=True)
    deploy_args = [
        "ai", "model-garden", "models", "deploy",
        "--model", model_id,
        "--machine-type", machine_type,
        "--accelerator-type", accel_type,
        "--accelerator-count", str(accel_count),
        "--project", project,
        "--region", region,
        "--endpoint-display-name", display_name,
        "--accept-eula",
    ]
    # Only passed when set: gcloud rejects an empty token value on some versions.
    hf_token = os.environ.get("HF_TOKEN", "").strip()
    if hf_token:
        deploy_args += ["--hugging-face-access-token", hf_token]

    gcloud(*deploy_args, dry_run=args.dry_run)

    print("\nModel deployed successfully.")
    print("Endpoint display name: %s" % display_name)
    print("\nTo test the endpoint, run:")
    print("  python scripts/test_model.py --config %s" % args.config)
    print("\nTo stop GPU costs when you are done:")
    print("  python scripts/undeploy_model.py --config %s" % args.config)
    return 0


if __name__ == "__main__":
    sys.exit(main())

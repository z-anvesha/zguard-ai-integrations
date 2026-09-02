#!/usr/bin/env python3
"""
Undeploy and delete the Vertex AI model endpoint to stop incurring GPU costs.

    GCP_PROJECT_ID=your-project python scripts/undeploy_model.py
    python scripts/undeploy_model.py --dry-run     # show what would be deleted

Environment:
    GCP_PROJECT_ID   required
    GCP_REGION       optional; falls back to deployment.region in the config
    CONFIG_FILE      optional; same as --config

Only endpoints whose display name matches the configured one exactly are
touched. Exits 0 when there is nothing to clean up, so it is safe to run
unconditionally from a pipeline's post/always block.
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
    list_endpoint_ids,
    load_config,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=os.environ.get("CONFIG_FILE", DEFAULT_CONFIG),
                        help="path to model-config.yaml (default: %s)" % DEFAULT_CONFIG)
    parser.add_argument("--dry-run", action="store_true",
                        help="list what would be deleted without deleting it")
    args = parser.parse_args()

    cfg = load_config(args.config)

    project = os.environ.get("GCP_PROJECT_ID", "").strip()
    if not project:
        die("GCP_PROJECT_ID environment variable is required")

    region = (os.environ.get("GCP_REGION", "").strip()
              or cfg.get("deployment", {}).get("region", "")
              or "us-central1")
    display_name = endpoint_display_name(cfg)

    print("Looking for endpoint: %s" % display_name)
    print("  Project: %s" % project)
    print("  Region:  %s" % region)
    if args.dry_run:
        print("  Mode:    DRY RUN — nothing will be deleted")
    print(flush=True)

    endpoint_ids = list_endpoint_ids(project, region, display_name, args.dry_run)
    if not endpoint_ids:
        print("No matching endpoints found. Nothing to clean up.")
        return 0

    for endpoint_id in endpoint_ids:
        print("==> Endpoint %s" % endpoint_id, flush=True)
        delete_endpoint(endpoint_id, project, region, args.dry_run)

    print("\nAll matching endpoints cleaned up. GPU costs stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

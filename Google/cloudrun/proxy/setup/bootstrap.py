#!/usr/bin/env python3
"""
bootstrap.py — one-time setup for the AI Guard on Apigee provisioning pipeline.

Run this once per project, from your own workstation with an account that has
Owner (or equivalent). It prepares everything the git-push pipeline needs, then
prints the push command that actually provisions Apigee.

What it creates (all idempotent — re-running is safe):
  1. enables the Google APIs the pipeline itself needs
  2. an Artifact Registry repo for the provisioner image
  3. the runtime service account the Cloud Run Job runs as, with the roles it
     needs to configure Apigee, manage the Vertex SA, and read the secret
  4. the `aiguard-api-key` secret in Secret Manager
  5. a Cloud Build trigger on this folder's cloudbuild.yaml

    python3 setup/bootstrap.py --project=YOUR_PROJECT_ID --region=us-central1 \
        --apigee-env=eval --repo=owner/repo --branch=main

The AI Guard API key is read from AIGUARD_API_KEY, or prompted for; it is never
passed on the command line, where it would land in your shell history.
"""

import argparse
import getpass
import os
import subprocess
import sys

# Roles the Cloud Run Job needs to do its work. apigee.admin covers importing and
# deploying bundles and writing the KVM; the iam roles let it create the Vertex SA
# and bind tokenCreator on it; secretAccessor lets it read the API key.
RUNTIME_ROLES = [
    "roles/apigee.admin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountUser",
    "roles/resourcemanager.projectIamAdmin",
    "roles/secretmanager.secretAccessor",
    "roles/serviceusage.serviceUsageAdmin",
]

BOOTSTRAP_APIS = [
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "apigee.googleapis.com",
]

SECRET_NAME = "aiguard-api-key"


def step(msg):
    print("\n==> %s" % msg, flush=True)


def ok(msg):
    print("    ok: %s" % msg, flush=True)


def die(msg):
    print("\nERROR: %s" % msg, file=sys.stderr)
    sys.exit(1)


def gcloud(*args, check=True, stdin=None):
    cmd = ["gcloud"] + [str(a) for a in args]
    proc = subprocess.run(cmd, capture_output=True, text=True, input=stdin)
    if check and proc.returncode != 0:
        die("%s failed: %s" % (" ".join(cmd), (proc.stderr or proc.stdout or "").strip()))
    return (proc.stdout or "").strip(), proc.returncode



def check_apigee(project, org, env):
    """Fail early and clearly when there is no Apigee org to configure.

    The pipeline configures an Apigee organization; it does not create one.
    Without this check the first failure would land deep inside the Cloud Run
    Job, as an opaque 404 from the management API.
    """
    step("Checking the Apigee organization")
    out, rc = gcloud("apigee", "organizations", "list", "--format", "value(name)", check=False)
    orgs = [o for o in out.splitlines() if o.strip()]

    if not orgs:
        die(
            "no Apigee organization exists on this account.\n\n"
            "  This pipeline configures an Apigee org (imports bundles, writes the KVM);\n"
            "  it does not create one. Provision an Apigee X organization first --\n"
            "  an evaluation org is free and sufficient:\n\n"
            "    Console:  https://console.cloud.google.com/apigee/overview?project=%s\n"
            "    REST:     POST https://apigee.googleapis.com/v1/organizations:provisionOrganization\n\n"
            "  Provisioning takes 30-45 minutes and creates an org, an environment and\n"
            "  an environment group. Re-run this bootstrap once it reports ACTIVE:\n\n"
            "    gcloud apigee organizations list" % project
        )

    if org not in orgs:
        die("Apigee org %r not found. Available: %s\n"
            "  Pass --apigee-org with one of those." % (org, ", ".join(orgs)))
    ok("Apigee org %s found" % org)

    # This list returns bare environment names, not objects: value(name) would
    # silently yield nothing and read as "no environments exist".
    out, rc = gcloud("apigee", "environments", "list", "--organization", org,
                     "--format", "value(.)", check=False)
    envs = [e for e in out.splitlines() if e.strip()]
    if rc != 0 or not envs:
        die("could not list environments in org %s. The org may still be provisioning;\n"
            "  check its state in the console and retry when it is ACTIVE." % org)
    if env not in envs:
        die("environment %r not found in org %s. Available: %s\n"
            "  Pass --apigee-env with one of those." % (env, org, ", ".join(envs)))
    ok("environment %s found" % env)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True, help="GCP project id")
    ap.add_argument("--region", default="us-central1", help="deployment region")
    ap.add_argument("--apigee-env", default="eval", help="Apigee environment name")
    ap.add_argument("--apigee-org", default="", help="Apigee org (default: the project id)")
    ap.add_argument("--repo", default="", help="GitHub repo as owner/name, for the trigger")
    ap.add_argument("--branch", default="main", help="branch the trigger watches")
    ap.add_argument("--envgroup-hostname", default="",
                    help="environment-group hostname, enables the smoke-test URL")
    ap.add_argument("--ar-repo", default="aiguard-apigee", help="Artifact Registry repo name")
    ap.add_argument("--job-name", default="aiguard-apigee-proxy-provisioner", help="Cloud Run Job name")
    ap.add_argument("--runtime-sa", default="",
                    help="reuse an existing service account for the Cloud Run Job "
                         "instead of creating aiguard-provisioner@PROJECT")
    ap.add_argument("--vertex-sa", default="",
                    help="reuse an existing service account for calling Vertex "
                         "instead of creating aiguard-vertex@PROJECT")
    ap.add_argument("--skip-trigger", action="store_true",
                    help="do everything except creating the Cloud Build trigger")
    args = ap.parse_args()

    project = args.project
    # A project may already have a service account set up for this; reuse it
    # rather than creating a second one with overlapping roles.
    runtime_sa = args.runtime_sa or ("aiguard-provisioner@%s.iam.gserviceaccount.com" % project)
    vertex_sa = args.vertex_sa or ("aiguard-vertex@%s.iam.gserviceaccount.com" % project)

    gcloud("config", "set", "project", project, "--quiet")

    # Nothing below creates anything until we know there is an org to configure.
    check_apigee(project, args.apigee_org or project, args.apigee_env)

    step("Enabling the APIs this bootstrap needs")
    gcloud("services", "enable", *BOOTSTRAP_APIS, "--project", project, "--quiet")
    ok(", ".join(a.split(".")[0] for a in BOOTSTRAP_APIS))

    step("Artifact Registry repo %s" % args.ar_repo)
    _, rc = gcloud("artifacts", "repositories", "describe", args.ar_repo,
                   "--location", args.region, "--project", project, check=False)
    if rc == 0:
        ok("repo exists")
    else:
        gcloud("artifacts", "repositories", "create", args.ar_repo,
               "--repository-format=docker", "--location", args.region,
               "--description", "Zscaler AI Guard on Apigee provisioner images",
               "--project", project, "--quiet")
        ok("repo created")

    step("Runtime service account %s" % runtime_sa)
    _, rc = gcloud("iam", "service-accounts", "describe", runtime_sa,
                   "--project", project, check=False)
    if rc == 0:
        ok("service account exists")
    elif args.runtime_sa:
        die("--runtime-sa %s does not exist; create it or omit the flag" % runtime_sa)
    else:
        gcloud("iam", "service-accounts", "create", runtime_sa.split("@")[0],
               "--project", project,
               "--display-name", "Zscaler AI Guard Apigee provisioner", "--quiet")
        ok("service account created")

    for role in RUNTIME_ROLES:
        gcloud("projects", "add-iam-policy-binding", project,
               "--member", "serviceAccount:" + runtime_sa,
               "--role", role, "--condition", "None", "--quiet")
        ok("granted %s" % role)

    step("Secret %s" % SECRET_NAME)
    api_key = os.environ.get("AIGUARD_API_KEY", "").strip()
    if not api_key:
        # Prompted rather than taken as a flag: a flag lands in shell history.
        api_key = getpass.getpass("AI Guard API key (input hidden): ").strip()
    if not api_key:
        die("no API key supplied")

    _, rc = gcloud("secrets", "describe", SECRET_NAME, "--project", project, check=False)
    if rc != 0:
        gcloud("secrets", "create", SECRET_NAME, "--replication-policy=automatic",
               "--project", project, "--quiet")
        ok("secret created")
    gcloud("secrets", "versions", "add", SECRET_NAME, "--data-file=-",
           "--project", project, stdin=api_key)
    ok("new secret version added")

    if args.skip_trigger or not args.repo:
        step("Skipping the Cloud Build trigger")
        if not args.repo:
            print("    (pass --repo=owner/name to create it)")
    else:
        step("Cloud Build trigger")
        owner, _, name = args.repo.partition("/")
        if not owner or not name:
            die("--repo must be owner/name")
        subs = ",".join([
            "_REGION=" + args.region,
            "_AR_REPO=" + args.ar_repo,
            "_JOB_NAME=" + args.job_name,
            "_RUNTIME_SA=" + runtime_sa,
            "_APIGEE_ORG=" + (args.apigee_org or ""),
            "_APIGEE_ENV=" + args.apigee_env,
            "_VERTEX_SA=" + vertex_sa,
            "_ENVGROUP_HOSTNAME=" + args.envgroup_hostname,
        ])
        # The GitHub-App connection is 1st-gen, so the trigger is created with
        # --region=global while the resources it deploys live in --region.
        _, rc = gcloud(
            "builds", "triggers", "create", "github",
            "--name", "aiguard-apigee-proxy",
            "--repo-owner", owner, "--repo-name", name,
            "--branch-pattern", "^%s$" % args.branch,
            "--build-config", "Google/cloudrun/proxy/cloudbuild.yaml",
            "--substitutions", subs,
            "--region", "global", "--project", project, "--quiet", check=False)
        ok("trigger created" if rc == 0 else "trigger not created (it may already exist)")

    print("""
Bootstrap complete.

  runtime SA : %s
  vertex SA  : %s   (created by the pipeline on first run)
  secret     : %s
  apigee     : org=%s env=%s

Next: push to the %s branch, and the trigger builds the provisioner image, runs
it as a Cloud Run Job, and configures Apigee end to end.

    git commit --allow-empty -m "provision AI Guard on Apigee" && git push

Watch it:

    gcloud builds list --region=global --limit=1 --project=%s
""" % (runtime_sa, vertex_sa, SECRET_NAME, args.apigee_org or project,
       args.apigee_env, args.branch, project))
    return 0


if __name__ == "__main__":
    sys.exit(main())

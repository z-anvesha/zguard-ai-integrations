#!/usr/bin/env python3
"""
provision_org.py — create an Apigee X evaluation org and everything it needs.

The main pipeline (setup/bootstrap.py + cloudbuild.yaml) *configures* an Apigee
organization: it imports bundles and writes the KVM. It does not create one.
This helper covers the step before that, for a project with no Apigee org yet.

It creates, in order, waiting for each long-running operation:

  1. the organization        (EVALUATION billing, CLOUD runtime, no VPC peering)
  2. a runtime instance      (the slow one -- typically 20-40 minutes)
  3. an environment
  4. an environment group + hostname
  5. the attachments: environment -> instance, environment -> envgroup

Every step checks before it creates, so re-running after an interruption resumes
rather than duplicating.

    python3 setup/provision_org.py --project=YOUR_PROJECT_ID --region=us-west1

An evaluation org is free and expires after 60 days. The region must match any
existing API Hub instance in the project -- the API rejects a mismatch with
"an API Hub instance already exists in location X".

Standard library only; authenticates with `gcloud auth print-access-token`.
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "https://apigee.googleapis.com/v1"


def step(msg):
    print("\n==> %s" % msg, flush=True)


def ok(msg):
    print("    ok: %s" % msg, flush=True)


def die(msg):
    print("\nERROR: %s" % msg, file=sys.stderr)
    sys.exit(1)


def token():
    proc = subprocess.run(["gcloud", "auth", "print-access-token"],
                          capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        die("gcloud auth print-access-token failed: %s" % proc.stderr.strip())
    return proc.stdout.strip()


def call(method, path, tok, body=None, absolute=False):
    """Returns (status, parsed). Never raises on HTTP errors — callers branch."""
    url = path if absolute else API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw[:400]}
    except urllib.error.URLError as exc:
        die("cannot reach the Apigee API: %s" % exc.reason)


def wait_operation(op_name, tok, label, timeout_min=60):
    """Poll a long-running operation until done, printing progress."""
    deadline = time.time() + timeout_min * 60
    while time.time() < deadline:
        status, body = call("GET", "/" + op_name, tok)
        if status != 200:
            die("polling %s failed (HTTP %s): %s" % (label, status, body))
        if body.get("done"):
            if "error" in body:
                die("%s failed: %s" % (label, body["error"]))
            ok("%s complete" % label)
            return body
        state = body.get("metadata", {}).get("state", "IN_PROGRESS")
        print("    %s: %s ..." % (label, state), flush=True)
        time.sleep(60)
    die("%s did not finish within %d minutes" % (label, timeout_min))


def ensure_org(project, region, tok):
    step("Organization %s" % project)
    status, body = call("GET", "/organizations/%s" % project, tok)
    if status == 200:
        ok("org exists (state=%s)" % body.get("state", "?"))
        return
    status, body = call("POST", "/organizations?parent=projects/%s" % project, tok, {
        "name": project,
        "analyticsRegion": region,
        "runtimeType": "CLOUD",
        "billingType": "EVALUATION",
        "disableVpcPeering": True,
    })
    if status not in (200, 201):
        die("org create failed (HTTP %s): %s" % (status, body))
    wait_operation(body["name"], tok, "organization", timeout_min=60)


def wait_instance_active(project, name, tok, timeout_min=60):
    """Wait until the instance reports ACTIVE.

    Existence is not readiness: a submitted instance is visible immediately with
    state=CREATING, and attaching an environment to one that is still creating
    fails. Poll the state itself rather than trusting the GET to succeed.
    """
    deadline = time.time() + timeout_min * 60
    while time.time() < deadline:
        status, body = call("GET", "/organizations/%s/instances/%s" % (project, name), tok)
        if status != 200:
            die("cannot read instance %s (HTTP %s): %s" % (name, status, body))
        state = body.get("state", "?")
        if state == "ACTIVE":
            ok("instance ACTIVE (host=%s)" % body.get("host"))
            return body
        if state in ("FAILED", "DELETING"):
            die("instance %s is %s" % (name, state))
        print("    instance: %s ..." % state, flush=True)
        time.sleep(60)
    die("instance %s did not become ACTIVE within %d minutes" % (name, timeout_min))


def ensure_instance(project, region, name, tok):
    step("Runtime instance %s (this is the slow one)" % name)
    status, body = call("GET", "/organizations/%s/instances/%s" % (project, name), tok)
    if status == 200:
        if body.get("state") == "ACTIVE":
            ok("instance exists and is ACTIVE")
            return
        ok("instance exists (state=%s) -- waiting for it" % body.get("state"))
        wait_instance_active(project, name, tok)
        return
    status, body = call("POST", "/organizations/%s/instances" % project, tok,
                        {"name": name, "location": region})
    if status not in (200, 201):
        die("instance create failed (HTTP %s): %s" % (status, body))
    wait_operation(body["name"], tok, "instance", timeout_min=60)
    wait_instance_active(project, name, tok)


def ensure_environment(project, env, tok):
    step("Environment %s" % env)
    status, _ = call("GET", "/organizations/%s/environments/%s" % (project, env), tok)
    if status == 200:
        ok("environment exists")
        return
    status, body = call("POST", "/organizations/%s/environments" % project, tok,
                        {"name": env, "deploymentType": "PROXY", "apiProxyType": "PROGRAMMABLE"})
    if status not in (200, 201):
        die("environment create failed (HTTP %s): %s" % (status, body))
    wait_operation(body["name"], tok, "environment", timeout_min=20)


def ensure_envgroup(project, group, hostname, tok):
    step("Environment group %s (%s)" % (group, hostname))
    status, _ = call("GET", "/organizations/%s/envgroups/%s" % (project, group), tok)
    if status == 200:
        ok("envgroup exists")
        return
    status, body = call("POST", "/organizations/%s/envgroups" % project, tok,
                        {"name": group, "hostnames": [hostname]})
    if status not in (200, 201):
        die("envgroup create failed (HTTP %s): %s" % (status, body))
    wait_operation(body["name"], tok, "envgroup", timeout_min=20)


def attach_env_to_instance(project, instance, env, tok):
    step("Attaching %s to instance %s" % (env, instance))
    status, body = call("GET", "/organizations/%s/instances/%s/attachments"
                        % (project, instance), tok)
    if status == 200 and any(a.get("environment") == env
                             for a in body.get("attachments", [])):
        ok("already attached")
        return
    status, body = call("POST", "/organizations/%s/instances/%s/attachments"
                        % (project, instance), tok, {"environment": env})
    if status not in (200, 201):
        die("instance attachment failed (HTTP %s): %s" % (status, body))
    wait_operation(body["name"], tok, "instance attachment", timeout_min=30)


def attach_env_to_group(project, group, env, tok):
    step("Attaching %s to envgroup %s" % (env, group))
    status, body = call("GET", "/organizations/%s/envgroups/%s/attachments"
                        % (project, group), tok)
    if status == 200 and any(a.get("environment") == env
                             for a in body.get("environmentGroupAttachments", [])):
        ok("already attached")
        return
    status, body = call("POST", "/organizations/%s/envgroups/%s/attachments"
                        % (project, group), tok, {"environment": env})
    if status not in (200, 201):
        die("envgroup attachment failed (HTTP %s): %s" % (status, body))
    wait_operation(body["name"], tok, "envgroup attachment", timeout_min=20)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True)
    ap.add_argument("--region", default="us-west1",
                    help="must match an existing API Hub instance, if any")
    ap.add_argument("--env", default="eval", help="environment name")
    ap.add_argument("--instance", default="eval-instance", help="runtime instance name")
    ap.add_argument("--envgroup", default="eval-group", help="environment group name")
    ap.add_argument("--hostname", default="",
                    help="envgroup hostname (default: <project>.example.com)")
    args = ap.parse_args()

    hostname = args.hostname or ("%s.example.com" % args.project)
    tok = token()

    print("project=%s region=%s env=%s instance=%s envgroup=%s hostname=%s"
          % (args.project, args.region, args.env, args.instance, args.envgroup, hostname))
    print("\nAn evaluation org is free and expires after 60 days.")
    print("Total time is typically 30-50 minutes, dominated by the instance.\n")

    ensure_org(args.project, args.region, tok)
    ensure_instance(args.project, args.region, args.instance, tok)
    ensure_environment(args.project, args.env, tok)
    ensure_envgroup(args.project, args.envgroup, hostname, tok)
    attach_env_to_instance(args.project, args.instance, args.env, tok)
    attach_env_to_group(args.project, args.envgroup, args.env, tok)

    step("Apigee is ready")
    print("""
  org       : %s
  env       : %s
  hostname  : %s

Next, run the pipeline bootstrap against it:

    python3 setup/bootstrap.py --project=%s --region=%s --apigee-env=%s \\
        --envgroup-hostname=%s --skip-trigger
""" % (args.project, args.env, hostname, args.project, args.region, args.env, hostname))
    return 0


if __name__ == "__main__":
    sys.exit(main())

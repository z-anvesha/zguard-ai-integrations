#!/usr/bin/env python3
"""
Remove everything deploy_demo.py created -- the function, the role, and the log
group Lambda creates implicitly -- and nothing else.

Uses boto3 directly, so the AWS CLI is not required.

Hard rule: this script only ever deletes resources whose names start with
"aiguardaws-". The guard below is not decoration; it is what makes running this
against a real account safe.

    python3 scripts/teardown_demo.py
"""

import os
import sys

FUNCTION = "aiguardaws-decorator-demo"
ROLE = "aiguardaws-decorator-demo-role"
LOG_GROUP = "/aws/lambda/" + FUNCTION
PREFIX = "aiguardaws-"
BASIC_EXECUTION = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def refuse_unless_prefixed(*names):
    """Never delete anything this demo did not create."""
    for name in names:
        if not name.lstrip("/").replace("aws/lambda/", "").startswith(PREFIX):
            print("refusing: %r is not %s*" % (name, PREFIX))
            sys.exit(1)


def delete_function(lam):
    print("==> deleting Lambda %s" % FUNCTION)
    try:
        lam.delete_function(FunctionName=FUNCTION)
    except lam.exceptions.ResourceNotFoundException:
        print("    (already gone)")


def delete_log_group(logs):
    print("==> deleting log group %s" % LOG_GROUP)
    try:
        logs.delete_log_group(logGroupName=LOG_GROUP)
    except logs.exceptions.ResourceNotFoundException:
        print("    (already gone)")


def delete_role(iam):
    print("==> deleting role %s" % ROLE)
    try:
        iam.get_role(RoleName=ROLE)
    except iam.exceptions.NoSuchEntityException:
        print("    (already gone)")
        return
    # A role cannot be deleted while policies are still attached to it.
    try:
        iam.detach_role_policy(RoleName=ROLE, PolicyArn=BASIC_EXECUTION)
    except iam.exceptions.NoSuchEntityException:
        pass
    try:
        iam.delete_role_policy(RoleName=ROLE, PolicyName="aiguardaws-bedrock-invoke")
    except iam.exceptions.NoSuchEntityException:
        pass
    iam.delete_role(RoleName=ROLE)


def main():
    refuse_unless_prefixed(FUNCTION, ROLE, LOG_GROUP)
    try:
        import boto3
    except ImportError:
        print("boto3 is not installed: pip install boto3")
        return 1

    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    delete_function(boto3.client("lambda", region_name=region))
    delete_log_group(boto3.client("logs", region_name=region))
    delete_role(boto3.client("iam"))
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Provisioner image for the Zscaler AI Guard on Apigee Cloud Run Job.
#
# Base: Google Cloud SDK (slim) — ships gcloud and Python 3. provision.py uses
# only the standard library, so nothing is installed on top: no jq, no zip, no
# pip packages. Zipping the bundles and parsing the management-API responses are
# done in Python.

FROM google/cloud-sdk:slim

WORKDIR /app

# The provisioning script and the Apigee bundles it deploys.
COPY provision.py /app/provision.py
COPY bundles/ /app/bundles/

RUN chmod +x /app/provision.py

# The Job runs the script to completion and exits. No long-running process.
ENTRYPOINT ["python3", "/app/provision.py"]

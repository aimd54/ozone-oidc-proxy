# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# Light Jupyter for the lakehouse overlay: PyIceberg + boto3 against the
# OIDC proxy — no Spark (the point is the auth flows, not the engine).
FROM python:3.12-slim

RUN pip install --no-cache-dir \
    jupyterlab~=4.4 \
    "pyiceberg[pyarrow,s3fs]~=0.9" \
    pandas \
    boto3 \
    requests

WORKDIR /home/lakehouse/notebooks
EXPOSE 8888

# Lab-only: no token/password — the port is published on localhost by the
# overlay for a PoC walkthrough, not for shared deployments.
CMD ["jupyter", "lab", "--ip=0.0.0.0", "--port=8888", "--no-browser", \
     "--allow-root", "--ServerApp.token=", "--ServerApp.password="]

# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0

FROM python:3.12-alpine
RUN pip install --no-cache-dir requests
COPY init.py /init.py
CMD ["python", "-u", "/init.py"]

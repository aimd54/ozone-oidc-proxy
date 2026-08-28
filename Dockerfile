# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/ozone-oidc-proxy ./cmd/proxy \
    && CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/credential-portal ./cmd/credential-portal

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
COPY --from=build /out/ozone-oidc-proxy /usr/local/bin/ozone-oidc-proxy
# Same image serves the credential portal (compose overlay overrides the
# entrypoint); keeping one image avoids a second build pipeline.
COPY --from=build /out/credential-portal /usr/local/bin/credential-portal
EXPOSE 9000 9090
USER nonroot
ENTRYPOINT ["/usr/local/bin/ozone-oidc-proxy"]
CMD ["-config", "/etc/ozone-oidc-proxy/config.yaml"]

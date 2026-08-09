# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY main.go .
RUN go mod init stub-issuer && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/stub-issuer .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/stub-issuer /usr/local/bin/stub-issuer
EXPOSE 8081
USER nonroot
ENTRYPOINT ["/usr/local/bin/stub-issuer"]

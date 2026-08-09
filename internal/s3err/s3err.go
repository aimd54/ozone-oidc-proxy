// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Package s3err renders S3-shaped error XML so SDK retry/backoff behavior
// stays correct when the proxy rejects a request itself.
package s3err

import (
	"encoding/xml"
	"fmt"
	"net/http"
)

// Common S3 error codes used by the proxy.
const (
	CodeAccessDenied                      = "AccessDenied"
	CodeInvalidAccessKeyID                = "InvalidAccessKeyId"
	CodeExpiredToken                      = "ExpiredToken"
	CodeInvalidToken                      = "InvalidToken"
	CodeSignatureDoesNotMatch             = "SignatureDoesNotMatch"
	CodeRequestTimeTooSkewed              = "RequestTimeTooSkewed"
	CodeAuthorizationHeaderMalformed      = "AuthorizationHeaderMalformed"
	CodeAuthorizationQueryParametersError = "AuthorizationQueryParametersError"
	CodeInvalidRequest                    = "InvalidRequest"
	CodeMissingSecurityHeader             = "MissingSecurityHeader"
	CodeInternalError                     = "InternalError"
	CodeServiceUnavailable                = "ServiceUnavailable"
)

type errorXML struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestID string   `xml:"RequestId"`
}

// Write sends one S3 error document.
func Write(w http.ResponseWriter, status int, code, message, resource, requestID string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprint(w, xml.Header)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	_ = enc.Encode(errorXML{Code: code, Message: message, Resource: resource, RequestID: requestID})
	fmt.Fprintln(w)
}

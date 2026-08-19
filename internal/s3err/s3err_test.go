// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package s3err

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// decoded mirrors the document an S3 client parses. It is declared here
// rather than reusing errorXML so that a change to the wire shape has to be
// made in two places deliberately, instead of a renamed field silently
// keeping the test green.
type decoded struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

func TestWriteRendersTheDocumentAClientParses(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusForbidden, CodeInvalidAccessKeyID,
		"The AWS access key ID you provided does not exist in our records.",
		"/bucket/key", "req-0001")

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, xml.Header) {
		t.Errorf("body does not begin with the XML declaration: %q",
			body[:min(len(body), 60)])
	}

	var got decoded
	if err := xml.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("body is not well-formed XML: %v\n%s", err, body)
	}
	if got.XMLName.Local != "Error" {
		t.Errorf("root element = %q, want Error", got.XMLName.Local)
	}
	if got.Code != CodeInvalidAccessKeyID {
		t.Errorf("Code = %q, want %q", got.Code, CodeInvalidAccessKeyID)
	}
	if !strings.Contains(got.Message, "does not exist") {
		t.Errorf("Message = %q", got.Message)
	}
	if got.Resource != "/bucket/key" {
		t.Errorf("Resource = %q, want /bucket/key", got.Resource)
	}
	if got.RequestID != "req-0001" {
		t.Errorf("RequestId = %q, want req-0001", got.RequestID)
	}
}

func TestWriteOmitsAnEmptyResourceButAlwaysCarriesARequestID(t *testing.T) {
	// Resource is optional in the S3 shape and carries a path, so an empty
	// element would advertise a resource of "". RequestId is not optional:
	// it is what a user quotes in a support request and what correlates a
	// rejection with the proxy's own log line.
	rec := httptest.NewRecorder()
	Write(rec, http.StatusBadRequest, CodeInvalidRequest, "no resource here", "", "req-0002")

	body := rec.Body.String()
	if strings.Contains(body, "<Resource>") {
		t.Errorf("empty Resource was rendered anyway:\n%s", body)
	}
	if !strings.Contains(body, "<RequestId>req-0002</RequestId>") {
		t.Errorf("RequestId missing or malformed:\n%s", body)
	}
}

// The codes are the contract with every AWS SDK: clients branch on these
// strings, so a typo changes retry behaviour rather than causing a failure
// anyone would notice. InvalidAccessKeyId in particular is spelled with a
// lowercase "d" by AWS, which is exactly the kind of thing that gets
// "corrected" during a refactor.
func TestErrorCodesRenderVerbatim(t *testing.T) {
	cases := []struct{ constant, want string }{
		{CodeAccessDenied, "AccessDenied"},
		{CodeInvalidAccessKeyID, "InvalidAccessKeyId"},
		{CodeExpiredToken, "ExpiredToken"},
		{CodeInvalidToken, "InvalidToken"},
		{CodeSignatureDoesNotMatch, "SignatureDoesNotMatch"},
		{CodeRequestTimeTooSkewed, "RequestTimeTooSkewed"},
		{CodeAuthorizationHeaderMalformed, "AuthorizationHeaderMalformed"},
		{CodeAuthorizationQueryParametersError, "AuthorizationQueryParametersError"},
		{CodeInvalidRequest, "InvalidRequest"},
		{CodeMissingSecurityHeader, "MissingSecurityHeader"},
		{CodeInternalError, "InternalError"},
		{CodeServiceUnavailable, "ServiceUnavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if tc.constant != tc.want {
				t.Fatalf("constant = %q, want %q", tc.constant, tc.want)
			}
			rec := httptest.NewRecorder()
			Write(rec, http.StatusForbidden, tc.constant, "m", "", "req")
			var got decoded
			if err := xml.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Code != tc.want {
				t.Errorf("rendered Code = %q, want %q", got.Code, tc.want)
			}
		})
	}
}

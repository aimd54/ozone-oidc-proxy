// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package sts

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/aimd54/ozone-oidc-proxy/internal/store"
)

// AWS error codes emitted by the STS handler.
const (
	codeValidationError       = "ValidationError"
	codeInvalidIdentityToken  = "InvalidIdentityToken"
	codeExpiredToken          = "ExpiredTokenException"
	codeIDPCommunicationError = "IDPCommunicationError"
	codeAccessDenied          = "AccessDenied"
	codeServiceFailure        = "ServiceFailure"
)

const stsXMLNS = "https://sts.amazonaws.com/doc/2011-06-15/"

type successData struct {
	Subject     string
	Provider    string
	RoleArn     string
	SessionName string
	Creds       store.Credentials
	RequestID   string
}

type assumeRoleResponse struct {
	XMLName xml.Name         `xml:"AssumeRoleWithWebIdentityResponse"`
	XMLNS   string           `xml:"xmlns,attr"`
	Result  assumeRoleResult `xml:"AssumeRoleWithWebIdentityResult"`
	Meta    responseMetadata `xml:"ResponseMetadata"`
}

type assumeRoleResult struct {
	SubjectFromWebIdentityToken string          `xml:"SubjectFromWebIdentityToken"`
	Audience                    string          `xml:"Audience,omitempty"`
	AssumedRoleUser             assumedRoleUser `xml:"AssumedRoleUser"`
	Credentials                 credentialsXML  `xml:"Credentials"`
	Provider                    string          `xml:"Provider"`
}

type assumedRoleUser struct {
	AssumedRoleID string `xml:"AssumedRoleId"`
	Arn           string `xml:"Arn"`
}

type credentialsXML struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type responseMetadata struct {
	RequestID string `xml:"RequestId"`
}

type errorResponse struct {
	XMLName   xml.Name  `xml:"ErrorResponse"`
	XMLNS     string    `xml:"xmlns,attr"`
	Error     errorBody `xml:"Error"`
	RequestID string    `xml:"RequestId"`
}

type errorBody struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func writeSuccess(w http.ResponseWriter, d successData) {
	resp := assumeRoleResponse{
		XMLNS: stsXMLNS,
		Result: assumeRoleResult{
			SubjectFromWebIdentityToken: d.Subject,
			AssumedRoleUser: assumedRoleUser{
				AssumedRoleID: "OZPXROLEID:" + d.SessionName,
				Arn:           d.RoleArn + "/" + d.SessionName,
			},
			Credentials: credentialsXML{
				AccessKeyID:     d.Creds.AccessKeyID,
				SecretAccessKey: d.Creds.SecretAccessKey,
				SessionToken:    d.Creds.SessionToken,
				Expiration:      d.Creds.ExpiresAt.UTC().Format(time.RFC3339),
			},
			Provider: d.Provider,
		},
		Meta: responseMetadata{RequestID: d.RequestID},
	}
	writeXML(w, http.StatusOK, resp)
}

func writeError(w http.ResponseWriter, status int, code, message, reqID string) {
	writeXML(w, status, errorResponse{
		XMLNS:     stsXMLNS,
		Error:     errorBody{Type: "Sender", Code: code, Message: message},
		RequestID: reqID,
	})
}

func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	fmt.Fprint(w, xml.Header)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	_ = enc.Encode(v)
	fmt.Fprintln(w)
}

func newRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(buf)
}

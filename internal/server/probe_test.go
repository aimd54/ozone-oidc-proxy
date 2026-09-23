// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"os"
	"regexp"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// blackboxModules is the part of alerts/blackbox.yml the probe depends on.
type blackboxModules struct {
	Modules map[string]struct {
		HTTP struct {
			ValidStatusCodes           []int    `yaml:"valid_status_codes"`
			FailIfBodyNotMatchesRegexp []string `yaml:"fail_if_body_not_matches_regexp"`
		} `yaml:"http"`
	} `yaml:"modules"`
}

// probeAccepts applies a module's checks the way blackbox_exporter does: the
// status must be listed, and the body must match every expression.
func probeAccepts(t *testing.T, codes []int, exprs []string, status int, body string) bool {
	t.Helper()
	if !slices.Contains(codes, status) {
		return false
	}
	for _, expr := range exprs {
		re, err := regexp.Compile(expr)
		if err != nil {
			t.Fatalf("module expression %q does not compile: %v", expr, err)
		}
		if !re.MatchString(body) {
			return false
		}
	}
	return true
}

// Refusals the S3 Gateway itself returned through a proxy running with strict
// mode off, recorded against a live Ozone. Both are 403s, which is why the
// probe cannot go by the status.
const (
	// An anonymous request, passed through unsigned.
	ozoneRefusesUnsigned = `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>InvalidRequest</Code>
  <Message>Error creating s3 auth info. The request may not be signed using AWS V4 signing algorithm, or might be invalid</Message>
  <Resource/>
  <RequestId/>
</Error>`
	// An authenticated user without the right, refused by Ozone's ACLs.
	ozoneRefusesUnauthorised = `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>User doesn't have the right to access this resource.</Message>
  <Resource>listBuckets</Resource>
  <RequestId>254ac66b-1a97-411d-a46a-3ce8694084a7</RequestId>
</Error>`
)

// The anonymous-request probe recognises the proxy's refusal by its body.
// Both sides of that are checked here against the handler that writes the
// refusal: the module must accept it, and must not accept a refusal Ozone
// wrote, which is what arrives once strict mode is off. Rewording the refusal
// breaks the probe, so it fails this test first.
func TestAnonymousProbeRecognisesOnlyTheProxysRefusal(t *testing.T) {
	raw, err := os.ReadFile("../../alerts/blackbox.yml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg blackboxModules
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("alerts/blackbox.yml: %v", err)
	}
	mod, ok := cfg.Modules["ozpx_anonymous_refused"]
	if !ok {
		t.Fatal("alerts/blackbox.yml has no ozpx_anonymous_refused module")
	}
	codes, exprs := mod.HTTP.ValidStatusCodes, mod.HTTP.FailIfBodyNotMatchesRegexp

	env := newEnv(t, strictCfg, defaultValidate)
	resp := mustDo(t, mustReq(t, http.MethodGet, env.proxy.URL+"/"))
	body := bodyOf(t, resp)
	if !probeAccepts(t, codes, exprs, resp.StatusCode, body) {
		t.Errorf("the probe rejects the proxy's own refusal (status %d, body %s): it would alert on a correct proxy",
			resp.StatusCode, body)
	}

	for name, body := range map[string]string{
		"unsigned":     ozoneRefusesUnsigned,
		"unauthorised": ozoneRefusesUnauthorised,
	} {
		if probeAccepts(t, codes, exprs, http.StatusForbidden, body) {
			t.Errorf("the probe accepts Ozone's own %s refusal: it would stay quiet with strict mode off", name)
		}
	}
}

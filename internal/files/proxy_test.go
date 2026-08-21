package files

import (
	"net/http"
	"testing"
)

/**
 * The upstream path comes from a TABLE, so no part of a caller's request reaches it.
 *
 * The obvious alternative, forwarding r.URL.Path with a prefix swapped, is how a request for
 * /v1/files/../../secrets becomes a request to the workspace for something else.
 */
func TestUpstreamPathsAreATable(t *testing.T) {
	for gate, want := range map[string]string{
		PathList:     "/files",
		PathContent:  "/files/content",
		PathDownload: "/download",
	} {
		got, ok := upstreamFor(gate)
		if !ok || got != want {
			t.Errorf("%s -> %q %v, want %q", gate, got, ok, want)
		}
	}

	for _, unknown := range []string{
		"/v1/files/../../secrets",
		"/v1/files/",
		"/v1/session",
		"/files",
		"",
		"/v1/download/../../etc/passwd",
	} {
		if _, ok := upstreamFor(unknown); ok {
			t.Errorf("%q was mapped to an upstream path", unknown)
		}
	}
}

/**
 * A PASS MAY ONLY ARRIVE IN THE AUTHORIZATION HEADER. A file browser's URLs end up in the ingress
 * access log and in a browser's history, and a credential in either is one somebody else can read.
 */
func TestBearerToken(t *testing.T) {
	good := &http.Request{Header: http.Header{"Authorization": {"Bearer runos_pass_v1.a.b"}}}
	if token, err := BearerToken(good); err != nil || token != "runos_pass_v1.a.b" {
		t.Fatalf("got %q %v", token, err)
	}

	// Case-insensitive scheme, as the HTTP spec requires.
	lower := &http.Request{Header: http.Header{"Authorization": {"bearer runos_pass_v1.a.b"}}}
	if _, err := BearerToken(lower); err != nil {
		t.Errorf("a lowercase scheme must be accepted: %v", err)
	}

	for _, bad := range []string{
		"",
		"Bearer",
		"Bearer ",
		"Basic abc",
		"runos_pass_v1.a.b",
		// A pass with a query string glued on means a client is building URLs somewhere it should
		// not be, and trimming it would hide that.
		"Bearer runos_pass_v1.a.b?user=root",
		"Bearer runos_pass_v1.a.b&x=1",
		"Bearer two tokens",
	} {
		req := &http.Request{Header: http.Header{"Authorization": {bad}}}
		if _, err := BearerToken(req); err == nil {
			t.Errorf("%q was accepted as a bearer token", bad)
		}
	}
}

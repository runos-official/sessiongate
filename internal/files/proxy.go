// Package files proxies the workspace's read-only file endpoints.
//
// WHY THESE ARE HTTP AND NOT A STREAM. Listing a directory, reading a file and downloading a project
// are separate requests with separate answers; a websocket would make each one a message in a
// protocol nobody needs. They share the session mechanism and nothing else.
//
// WHY THE PASS LIVES LONGER FOR THIS KIND. A file browser makes many requests over a minute or two
// of a person clicking about, and minting a pass per click would put the control plane back in the
// middle of every interaction. Five minutes, single use NOT enforced, and the reasoning is
// deliberate: a credential that is spent by the first request cannot serve a second, and a file
// listing is not a session.
package files

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runos-official/sessiongate/internal/pass"
	"github.com/runos-official/sessiongate/internal/workspace"
)

// The three paths served, and nothing else.
const (
	PathList     = "/v1/files"
	PathContent  = "/v1/files/content"
	PathDownload = "/v1/download"
)

// upstreamFor maps a gate path onto the workspace path that answers it.
//
// A TABLE, so no part of a caller's request reaches the upstream path. The obvious alternative,
// forwarding r.URL.Path with a prefix swapped, is how a request for /v1/files/../../secrets becomes
// a request to the workspace for something else.
func upstreamFor(gatePath string) (string, bool) {
	switch gatePath {
	case PathList:
		return "/files", true
	case PathContent:
		return "/files/content", true
	case PathDownload:
		return "/download", true
	default:
		return "", false
	}
}

// Timeout bounds one file request. A project download is the long one, so it is generous, but a
// workspace that has stopped answering must not hold a connection for ever.
const Timeout = 5 * time.Minute

// MaxResponseBytes bounds what the gate will relay for a listing or a file read. A download is
// streamed and is not subject to it: the point of a download is that it is large.
const MaxResponseBytes = 64 << 20

// Proxy forwards one verified file request to the workspace the pass names.
type Proxy struct {
	HTTP *http.Client
	Log  interface{ Warn(string, ...any) }
}

/*
Serve relays a request, taking EVERY part of the upstream request from verified values.

The path comes from a table, the host is built from the pass's service name, and the only thing that
survives from the caller's request is the query string, which the workspace validates itself against
the login's home directory. The pass is forwarded so the workspace can check it names that workspace.
*/
func (p *Proxy) Serve(w http.ResponseWriter, r *http.Request, payload *pass.Payload, token string) {
	upstreamPath, ok := upstreamFor(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	target, err := workspace.Resolve(payload)
	if err != nil {
		// A conductor bug rather than forgery: a forged pass never reaches here.
		http.Error(w, "this session names no workspace this gate can reach", http.StatusBadGateway)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), Timeout)
	defer cancel()

	endpoint := target.URL("http", upstreamPath)
	if raw := r.URL.RawQuery; raw != "" {
		endpoint += "?" + raw
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		http.Error(w, "the request could not be built", http.StatusInternalServerError)
		return
	}
	// The pass travels as a bearer token on this hop, which is the only header a workspace reads it
	// from. It goes no further: the workspace is the last party that needs it.
	req.Header.Set("Authorization", "Bearer "+token)
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}

	res, err := p.HTTP.Do(req)
	if err != nil {
		http.Error(w, "the workspace did not answer", http.StatusBadGateway)
		return
	}
	defer res.Body.Close()

	// Copy the headers a file response needs and NOTHING ELSE. Forwarding every upstream header
	// would relay Set-Cookie and anything else the workspace might grow, from a component whose only
	// job here is to move bytes.
	for _, name := range []string{"Content-Type", "Content-Length", "Content-Disposition", "Last-Modified"} {
		if v := res.Header.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
	// A file listing is per-person and per-moment. Nothing between here and the browser may keep it.
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(res.StatusCode)

	var body io.Reader = res.Body
	if r.URL.Path != PathDownload {
		body = io.LimitReader(res.Body, MaxResponseBytes)
	}
	if _, err := io.Copy(w, body); err != nil && p.Log != nil {
		p.Log.Warn("file response was cut short", "path", r.URL.Path, "error", err.Error())
	}
}

// BearerToken pulls the pass out of an Authorization header.
//
// The ONLY place a pass may be on this path. Never a query string: a file browser's URLs end up in
// the ingress access log and in a browser's history, and a credential in either is a credential
// somebody else can read.
func BearerToken(r *http.Request) (string, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", fmt.Errorf("no bearer token")
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", fmt.Errorf("no bearer token")
	}
	// Refused rather than trimmed: a pass with a query string glued to it means a client is building
	// URLs somewhere it should not be.
	if strings.ContainsAny(token, " ?&#") {
		return "", fmt.Errorf("the token is not a bare pass")
	}
	return token, nil
}

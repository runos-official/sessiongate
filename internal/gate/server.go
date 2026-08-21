package gate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/runos-official/sessiongate/internal/pass"
	"github.com/runos-official/sessiongate/internal/replay"
)

// Server is the gate's public door.
//
// EXACTLY FOUR PATHS, and everything else is a 404. The websocket path is a CONSTANT: it names no
// account, cluster, VM or workspace, so there is no path-versus-pass cross-check for a refactor to
// quietly drop, and no identifier in an access log.
type Server struct {
	Config   Config
	Upstream *Upstream
	Memory   *replay.Memory
	Claimer  replay.Claimer
	Log      *slog.Logger
	Now      func() time.Time

	// MaxSessions bounds concurrency. A gate with no ceiling is a gate that dies of its own success
	// and takes every live session with it.
	MaxSessions int32
	live        atomic.Int32
	draining    atomic.Bool
}

// streamKinds are what the websocket door serves. ws.files is deliberately absent: it is an HTTP
// kind, and serving it here would mean one door with two very different lifetimes behind it.
var streamKinds = []pass.Kind{pass.KindVMSSH, pass.KindVMSerial, pass.KindVMVNC, pass.KindWSTerminal}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/session", s.handleSession)
	// Everything else, including every path that looks close, is a 404 with no body worth reading.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// Drain stops accepting new sessions. Existing ones keep running.
func (s *Server) Drain() { s.draining.Store(true) }

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	req := Request{
		Path:         r.URL.Path,
		RawQuery:     r.URL.RawQuery,
		Origin:       r.Header.Get("Origin"),
		Subprotocols: offeredSubprotocols(r),
		AllowedKinds: streamKinds,
	}

	if s.draining.Load() {
		// Pre-handshake, because a draining gate has nothing to say that needs a close code and a
		// client should retry elsewhere immediately.
		http.Error(w, "this gate is draining", http.StatusServiceUnavailable)
		return
	}

	decision := Verify(req, s.Config, s.now)
	if decision.HTTPStatus != 0 {
		// Refused before the handshake: decidable without trusting the caller, so it costs neither
		// side an upgrade.
		s.Log.Warn("session refused before handshake",
			"status", decision.HTTPStatus, "reason", decision.LogReason, "remote", clientIP(r))
		http.Error(w, decision.ClientText, decision.HTTPStatus)
		return
	}

	// From here every refusal completes the handshake and closes with a code, because a browser can
	// read no body from a refused upgrade: without this a client sees "connection failed" and
	// cannot tell an expired pass from a dead cluster.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// ONLY the protocol name is advertised, never the pass. The library echoes the first of ITS
		// list that the client also offered, so the pass never reaches a response header, devtools,
		// or a proxy log that records response headers.
		Subprotocols: []string{SessionProtocol},
		// The origin check is ours, above, and it is deliberately not the library's: the library
		// compares Origin to the request Host, which behind Traefik is whatever host header arrived.
		InsecureSkipVerify: true,
	})
	if err != nil {
		s.Log.Warn("handshake failed", "error", err, "remote", clientIP(r))
		return
	}

	if !decision.Allow {
		s.closeWith(conn, decision)
		s.Log.Warn("session refused",
			"close", decision.CloseCode, "reason", decision.LogReason, "remote", clientIP(r))
		return
	}

	p := decision.Payload
	logger := s.Log.With("jti", p.JTI, "kind", string(p.Kind), "sub", p.Sub)

	if n := s.live.Add(1); n > s.MaxSessions {
		s.live.Add(-1)
		s.closeWith(conn, refuseClose(CloseAtCapacity, "this gate is at capacity",
			fmt.Sprintf("%d live sessions", n-1)))
		logger.Warn("session refused at capacity", "live", n-1)
		return
	}
	defer s.live.Add(-1)

	// STEP 10: burn the pass. BEFORE the dial, so a pass is spent by the attempt rather than by the
	// success: a pass that survives a failed dial is a pass that can be retried by whoever captured
	// it.
	if err := s.claim(r.Context(), p); err != nil {
		switch {
		case errors.Is(err, replay.ErrReplayed):
			s.closeWith(conn, refuseClose(CloseReplayed, "this session pass has already been used", "replayed"))
			logger.Warn("session refused as replayed")
		default:
			// FAIL CLOSED. The claim could not be CONFIRMED, so the session does not open. This is
			// the branch an adversarial review found the design silent about, and silence here is a
			// fail-open.
			s.closeWith(conn, refuseClose(CloseFarEnd, "the cluster could not confirm this session", "claim unavailable"))
			logger.Error("session refused: the single-use claim could not be confirmed", "error", err)
		}
		return
	}

	upstream, err := s.dial(r.Context(), p, decision.Token)
	if err != nil {
		// NOTHING UNDOES THE CLAIM HERE. The tempting cleanup is exactly the hole: a gate that
		// releases the pass when the dial fails has made that pass replayable by whoever holds it.
		s.closeWith(conn, refuseClose(CloseFarEnd, "the cluster refused this session", "dial: "+err.Error()))
		logger.Warn("far end refused", "error", err)
		return
	}
	defer upstream.Close(websocket.StatusNormalClosure, "")

	logger.Info("session open", "waited", s.now().Sub(start).String())
	pipeErr := Pipe(r.Context(), conn, upstream)
	logger.Info("session closed", "duration", s.now().Sub(start).String(), "error", errText(pipeErr))
	conn.Close(websocket.StatusNormalClosure, "")
}

// claim burns the pass: memory first for the common retry, then the durable Lease.
func (s *Server) claim(ctx context.Context, p *pass.Payload) error {
	if s.Memory.Take(p.JTI, p.ExpiresAt()) {
		return replay.ErrReplayed
	}
	return s.Claimer.Claim(ctx, p.JTI, p.ExpiresAt())
}

func (s *Server) dial(ctx context.Context, p *pass.Payload, token string) (*websocket.Conn, error) {
	if p.Kind.IsVM() {
		return s.Upstream.DialVM(ctx, p)
	}
	// The workspace verifies the pass again, so the raw token travels one more hop. It goes no
	// further than that: the workspace is the last party that needs it.
	return s.Upstream.DialWorkspace(ctx, p, token)
}

func (s *Server) closeWith(conn *websocket.Conn, d Decision) {
	conn.Close(websocket.StatusCode(d.CloseCode), d.ClientText)
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// clientIP is for logs only. It reads X-Forwarded-For because Traefik is in front, and it is never
// used for a decision: a header a client can set is not an identity.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	return r.RemoteAddr
}

/*
offeredSubprotocols reads what the client offered, from either header form.

A client may send one comma-joined Sec-WebSocket-Protocol header or several separate ones, and both
are legal. The websocket library does not export its own reader for this, and parsing it here is
better anyway: the gate decides exactly what a token is, rather than inheriting a decision from a
dependency that could change under it.

Splitting on commas is safe for a base64url pass, which contains none.
*/
func offeredSubprotocols(r *http.Request) []string {
	var out []string
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				out = append(out, token)
			}
		}
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// AdminHandler serves the probes and metrics on a SEPARATE listener that is not in the Ingress.
//
// Deliberately removes runostty's public unauthenticated GET /health, which is a working oracle for
// "does user X have a workspace on cluster Y": anyone could enumerate a customer's staff by asking.
func AdminHandler(ready func() bool, live func() int32) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP runos_session_gate_live_sessions Sessions currently open.\n")
		fmt.Fprintf(w, "# TYPE runos_session_gate_live_sessions gauge\n")
		fmt.Fprintf(w, "runos_session_gate_live_sessions %d\n", live())
	})
	return mux
}

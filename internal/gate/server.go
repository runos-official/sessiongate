package gate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/runos-official/sessiongate/internal/files"
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
	// Files serves the read-only file endpoints.
	Files *files.Proxy
	Log   *slog.Logger
	Now   func() time.Time

	// MaxSessions bounds concurrency. A gate with no ceiling is a gate that dies of its own success
	// and takes every live session with it.
	MaxSessions int32
	/*
	 * MaxPerSubject stops ONE person filling the gate.
	 *
	 * Without it, an authorized user opening MaxSessions terminals and never typing denies every
	 * other person on the cluster for as long as those TCP connections survive, and a half-open
	 * connection behind a NAT that drops state without a FIN reaches the same place with no intent
	 * at all. A per-subject ceiling turns a cluster-wide denial into one person's own problem.
	 */
	MaxPerSubject int32
	/*
	 * MaxSessionAge is an absolute limit on one session.
	 *
	 * The PASS lives sixty seconds; the SESSION it opens had no upper bound whatsoever. Nothing in
	 * the gate pinged, timed out or aged a connection, so a session could outlive the credential
	 * that authorized it by any margin, including for ever. Zero disables it, which is a deliberate
	 * escape hatch for an operator who would rather have long consoles than the bound.
	 */
	MaxSessionAge time.Duration
	live          atomic.Int32
	draining      atomic.Bool

	// open is every live session, so a shutdown can END them rather than let the process exit from
	// under them. See CloseAll.
	openMu     sync.Mutex
	open       map[string]*websocket.Conn
	perSubject map[string]int32
}

// streamKinds are what the websocket door serves. ws.files is deliberately absent: it is an HTTP
// kind, and serving it here would mean one door with two very different lifetimes behind it.
var streamKinds = []pass.Kind{pass.KindVMSSH, pass.KindVMSerial, pass.KindVMVNC, pass.KindWSTerminal}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/session", s.handleSession)
	// The file kind. Separate handlers because these are ordinary HTTP requests with ordinary
	// answers, and because they are a DIFFERENT GRANT: a terminal pass must not read files and a
	// file pass must not open a shell.
	mux.HandleFunc("GET "+files.PathList, s.handleFiles)
	mux.HandleFunc("GET "+files.PathContent, s.handleFiles)
	mux.HandleFunc("GET "+files.PathDownload, s.handleFiles)
	// Everything else, including every path that looks close, is a 404 with no body worth reading.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// Drain stops accepting new sessions. Existing ones keep running.
func (s *Server) Drain() { s.draining.Store(true) }

// Live is how many sessions are open, so a shutdown can wait for them.
func (s *Server) Live() int32 { return s.live.Load() }

/*
CloseAll ends every live session with a stated reason.

WHY IT EXISTS. Draining keeps existing sessions while the grace period lasts, and then the process
exits. Without this, that exit drops every survivor by closing the TCP with no close frame, and a
frameless drop is precisely what a client cannot interpret: it looks identical to a dead cluster, a
broken network and a refused pass. A person mid-command deserves better than a client that shrugs.

4001 is "the gate is going away". A client that sees it knows to mint a new pass and reconnect,
which is a completely different action from what it does on 4401 or 4502.
*/
func (s *Server) CloseAll(code int, reason string) int {
	s.openMu.Lock()
	conns := make([]*websocket.Conn, 0, len(s.open))
	for _, c := range s.open {
		conns = append(conns, c)
	}
	s.openMu.Unlock()

	/*
	 * CONCURRENTLY, and that is not a micro-optimisation.
	 *
	 * coder/websocket's Close writes a close frame and then WAITS UP TO FIVE SECONDS for the peer's
	 * close frame. Closing serially would therefore take up to five seconds PER SESSION: at the
	 * gate's default ceiling of 128 that is over ten minutes, far past any pod's grace period, so
	 * the kubelet would kill the process partway through and every session after the first few
	 * would be dropped with no close frame after all. The whole point of this function is to avoid
	 * exactly that.
	 *
	 * MEASURED: one session took the full five seconds to close in a test where the peer was not
	 * reading, which is how this was noticed.
	 */
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(conn *websocket.Conn) {
			defer wg.Done()
			// Best effort by nature: a connection that has already gone cannot be told anything, and
			// a failure here must not stop the others being told.
			_ = conn.Close(websocket.StatusCode(code), reason)
		}(c)
	}

	// Bounded. A peer that never answers the close handshake must not hold the shutdown open, and
	// its connection dies with the process a moment later regardless.
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(6 * time.Second):
	}
	return len(conns)
}

// addForSubject changes one subject's live count and returns the new value.
func (s *Server) addForSubject(sub string, delta int32) int32 {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	if s.perSubject == nil {
		s.perSubject = map[string]int32{}
	}
	s.perSubject[sub] += delta
	n := s.perSubject[sub]
	if n <= 0 {
		// Removed rather than left at zero: a map keyed by subject that never forgets is a slow leak
		// on a cluster with staff turnover.
		delete(s.perSubject, sub)
	}
	return n
}

func (s *Server) track(jti string, conn *websocket.Conn) {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	if s.open == nil {
		s.open = map[string]*websocket.Conn{}
	}
	s.open[jti] = conn
}

func (s *Server) untrack(jti string) {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	delete(s.open, jti)
}

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

	// One person may not fill the gate. Counted per SUBJECT rather than per connection source: the
	// source is a proxy address here, and the thing worth bounding is a person's own appetite.
	if s.MaxPerSubject > 0 {
		if n := s.addForSubject(p.Sub, 1); n > s.MaxPerSubject {
			s.addForSubject(p.Sub, -1)
			s.closeWith(conn, refuseClose(CloseAtCapacity,
				"you already have as many sessions open as this cluster allows",
				fmt.Sprintf("subject holds %d sessions", n-1)))
			logger.Warn("session refused: this subject is at its own ceiling", "held", n-1)
			return
		}
		defer s.addForSubject(p.Sub, -1)
	}

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

	// Tracked so a shutdown can END this session with a reason rather than letting the process exit
	// from under it. Untracked before the pipe's own close, so a session that ends normally is never
	// closed twice.
	s.track(p.JTI, conn)
	defer s.untrack(p.JTI)

	/*
	 * AN ABSOLUTE LIMIT ON THE SESSION, closed with a STATUS rather than by cancelling the pipe.
	 *
	 * Cancelling the pipe's context would drop the connection with no close frame, which is the one
	 * ending a client cannot interpret; see the comment on Pipe. Closing both ends with a status
	 * makes the blocked reads return a proper close error and the client learns why.
	 */
	if s.MaxSessionAge > 0 {
		timer := time.AfterFunc(s.MaxSessionAge, func() {
			logger.Warn("session reached its time limit", "limit", s.MaxSessionAge.String())
			_ = conn.Close(websocket.StatusCode(CloseDraining),
				"this session reached its time limit; open another")
			_ = upstream.Close(websocket.StatusGoingAway, "")
		})
		defer timer.Stop()
	}

	logger.Info("session open", "waited", s.now().Sub(start).String())
	pipeErr := Pipe(r.Context(), conn, upstream)
	logger.Info("session closed", "duration", s.now().Sub(start).String(), "error", errText(pipeErr))
	conn.Close(websocket.StatusNormalClosure, "")
}

/*
handleFiles serves the read-only file endpoints.

REFUSED BEFORE THE WORK, with an ordinary HTTP status, because these are ordinary requests: a client
can read a body here, so there is no reason to complete anything before saying no. That is the
opposite of the websocket path, where a browser can read no body from a refused upgrade and the
refusal has to arrive as a close code.

SINGLE USE IS NOT CLAIMED FOR THIS KIND, deliberately. A file browser makes many requests over a
minute or two of somebody clicking about, and a credential spent by the first request cannot serve
the second. The bound on this kind is its five-minute lifetime and the fact that it can only ever
read one workspace's files.
*/
func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	if s.draining.Load() {
		http.Error(w, "this gate is draining", http.StatusServiceUnavailable)
		return
	}

	token, err := files.BearerToken(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "a session pass is required", http.StatusUnauthorized)
		return
	}

	p, err := pass.Verify(token, s.Config.Keys, s.now, s.Config.Skew)
	if err != nil {
		// One message for every cause, as everywhere else: the gate must not tell a prober which
		// guess was closer. The real reason goes to the gate's own log.
		s.Log.Warn("file request refused", "reason", err.Error(), "remote", clientIP(r))
		http.Error(w, refusedText, http.StatusUnauthorized)
		return
	}
	if p.AID != s.Config.AID || p.CID != s.Config.CID {
		http.Error(w, "this pass is for another cluster", http.StatusForbidden)
		return
	}
	if p.Kind != pass.KindWSFiles {
		// A terminal pass must not read files. Both name this workspace and both are workspace
		// kinds, but they are different grants with different lifetimes and different doors.
		s.Log.Warn("a non-file pass was presented to a file endpoint", "kind", string(p.Kind))
		http.Error(w, refusedText, http.StatusUnauthorized)
		return
	}

	s.Files.Serve(w, r, p, token)
}

/*
claim burns the pass: memory first for the common retry, then the durable Lease.

THE MEMORY ENTRY IS GIVEN BACK WHEN THE DURABLE CLAIM COULD NOT BE CONFIRMED, and that asymmetry is
the whole subtlety here.

Without it, ONE transient apiserver fault burnt the pass in this process for ever while creating no
Lease at all. The next attempt with the same pass hit the memory layer and was told "already used",
which is a LIE: it was never used, nothing was recorded anywhere durable, and the same pass presented
to a second replica would have opened a session. The person retrying is told the one thing that makes
them stop retrying, and the operator sees a replay that never happened.

Only ErrUnavailable gives the entry back. ErrReplayed must not: that means the Lease exists, the pass
really is spent, and forgetting it here would let this process serve it again.
*/
func (s *Server) claim(ctx context.Context, p *pass.Payload) error {
	if s.Memory.Take(p.JTI, p.ExpiresAt()) {
		return replay.ErrReplayed
	}
	err := s.Claimer.Claim(ctx, p.JTI, p.ExpiresAt())
	if err != nil && errors.Is(err, replay.ErrUnavailable) {
		s.Memory.Forget(p.JTI)
	}
	return err
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

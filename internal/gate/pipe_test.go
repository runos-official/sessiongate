package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/runos-official/sessiongate/internal/pass"
	"github.com/runos-official/sessiongate/internal/replay"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

/*
A SESSION MUST END WITH A CLOSE FRAME.

MEASURED against a real CLI: the first version of Pipe cancelled a derived context to unblock the
other direction, and coder/websocket closes a connection abruptly when a read's context is cancelled.
The TCP went away with no close frame, and the client reported

	Error: failed to get reader: failed to read frame header: EOF

for a session that had worked perfectly. That client is RIGHT to refuse a frameless drop: it is
indistinguishable from a session that died, and treating it as clean is how a broken session reports
success. The gate is what has to end cleanly.

These tests run two real websocket connections through Pipe rather than mocks, because the bug lived
entirely in what the library does with a real connection.
*/

// echoServer accepts a websocket and hands it to fn.
func wsServer(t *testing.T, fn func(ctx context.Context, c *websocket.Conn)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		fn(r.Context(), c)
	}))
}

func dial(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(context.Background(), url, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	return c
}

func TestPipeEndsTheClientWithACloseFrame(t *testing.T) {
	// The far end sends one message then closes normally, which is what a shell exiting looks like.
	upstreamSrv := wsServer(t, func(ctx context.Context, c *websocket.Conn) {
		_ = c.Write(ctx, websocket.MessageBinary, []byte("hello"))
		c.Close(websocket.StatusNormalClosure, "")
	})
	defer upstreamSrv.Close()

	// The gate: accept a client, dial the far end, pipe.
	gateSrv := wsServer(t, func(ctx context.Context, client *websocket.Conn) {
		upstream, _, err := websocket.Dial(ctx, "ws"+upstreamSrv.URL[4:], nil)
		if err != nil {
			client.Close(websocket.StatusInternalError, "dial")
			return
		}
		defer upstream.Close(websocket.StatusNormalClosure, "")
		_ = Pipe(ctx, client, upstream)
		client.Close(websocket.StatusNormalClosure, "")
	})
	defer gateSrv.Close()

	client := dial(t, "ws"+gateSrv.URL[4:])
	defer client.CloseNow()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, data, err := client.Read(ctx); err != nil || string(data) != "hello" {
		t.Fatalf("expected the far end's message, got %q %v", data, err)
	}

	_, _, err := client.Read(ctx)
	status := websocket.CloseStatus(err)
	if status == -1 {
		t.Fatalf("THE SESSION ENDED WITHOUT A CLOSE FRAME: %v\n"+
			"A client cannot tell this from a dropped connection, which is exactly the bug this "+
			"test exists for.", err)
	}
	if status != websocket.StatusNormalClosure {
		t.Fatalf("closed with %d, want %d: the far end closed normally and that must carry across",
			status, websocket.StatusNormalClosure)
	}
}

/** The other direction: the CLIENT goes away, and the far end must be closed rather than left open. */
func TestPipeClosesTheFarEndWhenTheClientLeaves(t *testing.T) {
	farEndClosed := make(chan websocket.StatusCode, 1)
	upstreamSrv := wsServer(t, func(ctx context.Context, c *websocket.Conn) {
		_, _, err := c.Read(ctx)
		farEndClosed <- websocket.CloseStatus(err)
	})
	defer upstreamSrv.Close()

	gateSrv := wsServer(t, func(ctx context.Context, client *websocket.Conn) {
		upstream, _, err := websocket.Dial(ctx, "ws"+upstreamSrv.URL[4:], nil)
		if err != nil {
			return
		}
		_ = Pipe(ctx, client, upstream)
	})
	defer gateSrv.Close()

	client := dial(t, "ws"+gateSrv.URL[4:])
	client.Close(websocket.StatusNormalClosure, "done")

	select {
	case status := <-farEndClosed:
		if status == -1 {
			t.Fatal("the far end was dropped without a close frame when the client left")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the far end was never closed: a half-pipe outlived the session")
	}
}

/** Bytes flow both ways while the session is open. */
func TestPipeCarriesBytesBothWays(t *testing.T) {
	upstreamSrv := wsServer(t, func(ctx context.Context, c *websocket.Conn) {
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			if err := c.Write(ctx, typ, append([]byte("echo:"), data...)); err != nil {
				return
			}
		}
	})
	defer upstreamSrv.Close()

	gateSrv := wsServer(t, func(ctx context.Context, client *websocket.Conn) {
		upstream, _, err := websocket.Dial(ctx, "ws"+upstreamSrv.URL[4:], nil)
		if err != nil {
			return
		}
		defer upstream.Close(websocket.StatusNormalClosure, "")
		_ = Pipe(ctx, client, upstream)
	})
	defer gateSrv.Close()

	client := dial(t, "ws"+gateSrv.URL[4:])
	defer client.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, msg := range []string{"one", "two", "three"} {
		if err := client.Write(ctx, websocket.MessageBinary, []byte(msg)); err != nil {
			t.Fatal(err)
		}
		_, data, err := client.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "echo:"+msg {
			t.Fatalf("got %q, want %q", data, "echo:"+msg)
		}
	}
}

/*
A SHUTDOWN MUST END LIVE SESSIONS WITH A REASON.

Draining keeps existing sessions while the grace period lasts, and then the process exits. Without
CloseAll that exit drops every survivor by closing the TCP with no close frame, which is the one
ending a client cannot interpret: identical to a dead cluster, a broken network and a refused pass.

MEASURED on the cluster before this existed: a session held through a rollout restart simply stopped
answering, and the client's read expired with "context deadline exceeded" and no status at all.
*/
func TestCloseAllEndsSessionsWithAStatedReason(t *testing.T) {
	srv := &Server{}

	gateSrv := wsServer(t, func(ctx context.Context, client *websocket.Conn) {
		srv.track("jti-1", client)
		defer srv.untrack("jti-1")
		// Stand in for a live session: read until the other side is closed.
		for {
			if _, _, err := client.Read(ctx); err != nil {
				return
			}
		}
	})
	defer gateSrv.Close()

	client := dial(t, "ws"+gateSrv.URL[4:])
	defer client.CloseNow()

	// Let the handler register the session before ending it, and FAIL if it never does. The first
	// version of this loop just ran out and carried on, which made the test take exactly its own
	// timeout and told nobody why.
	registered := false
	waitStart := time.Now()
	for time.Since(waitStart) < 5*time.Second {
		srv.openMu.Lock()
		n := len(srv.open)
		srv.openMu.Unlock()
		if n == 1 {
			registered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !registered {
		t.Fatalf("the session was never registered, so CloseAll below would prove nothing")
	}
	t.Logf("session registered after %s", time.Since(waitStart).Round(time.Millisecond))

	if closed := srv.CloseAll(CloseDraining, "the session gate is restarting; reconnect"); closed != 1 {
		t.Fatalf("CloseAll reported %d sessions, want 1", closed)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err := client.Read(ctx)
	status := websocket.CloseStatus(err)
	if status == -1 {
		t.Fatalf("the session was dropped with no close frame: %v", err)
	}
	if int(status) != CloseDraining {
		t.Fatalf("closed with %d, want %d so a client knows to reconnect", status, CloseDraining)
	}
}

/** CloseAll on a gate with nothing open is a no-op, not a panic. */
func TestCloseAllWithNoSessions(t *testing.T) {
	srv := &Server{}
	if n := srv.CloseAll(CloseDraining, "x"); n != 0 {
		t.Fatalf("reported %d sessions on an idle gate", n)
	}
}

/*
CLOSING MANY SESSIONS MUST NOT TAKE MANY TIMES AS LONG AS CLOSING ONE.

coder/websocket's Close waits up to five seconds for the peer's close frame. Serially, the gate's
default ceiling of 128 sessions would take over ten minutes to shut down: the kubelet would kill the
process partway through and most sessions would be dropped with no close frame, which is the exact
outcome CloseAll exists to prevent.
*/
func TestCloseAllDoesNotTakeFiveSecondsPerSession(t *testing.T) {
	srv := &Server{}
	const sessions = 8

	gateSrv := wsServer(t, func(ctx context.Context, client *websocket.Conn) {
		id := fmt.Sprintf("jti-%p", client)
		srv.track(id, client)
		defer srv.untrack(id)
		for {
			if _, _, err := client.Read(ctx); err != nil {
				return
			}
		}
	})
	defer gateSrv.Close()

	clients := make([]*websocket.Conn, 0, sessions)
	for i := 0; i < sessions; i++ {
		c := dial(t, "ws"+gateSrv.URL[4:])
		defer c.CloseNow()
		clients = append(clients, c)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		srv.openMu.Lock()
		n := len(srv.open)
		srv.openMu.Unlock()
		if n == sessions {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	start := time.Now()
	closed := srv.CloseAll(CloseDraining, "restarting")
	elapsed := time.Since(start)
	t.Logf("closed %d sessions in %s", closed, elapsed.Round(time.Millisecond))

	if closed != sessions {
		t.Fatalf("closed %d of %d", closed, sessions)
	}
	// Serial would be at least 5s x 8 = 40s. Concurrent is bounded by one peer's timeout.
	if elapsed > 8*time.Second {
		t.Fatalf("closing %d sessions took %s, which scales with the session count rather than "+
			"being bounded: a full gate would outlast its own grace period", sessions, elapsed)
	}
}

/*
ONE PERSON MUST NOT BE ABLE TO FILL THE GATE.

Without a per-subject ceiling, an authorized user who opens the gate's whole capacity and never
types denies every other person on the cluster for as long as those TCP connections survive. A
half-open connection behind a NAT that drops state without a FIN reaches the same place with no
intent at all.
*/
func TestPerSubjectCeiling(t *testing.T) {
	srv := &Server{MaxSessions: 100, MaxPerSubject: 3}

	for i := 0; i < 3; i++ {
		if n := srv.addForSubject("alice", 1); n > srv.MaxPerSubject {
			t.Fatalf("session %d was over the ceiling at %d", i+1, n)
		}
	}
	if n := srv.addForSubject("alice", 1); n <= srv.MaxPerSubject {
		t.Fatalf("a fourth session was allowed at %d", n)
	}
	srv.addForSubject("alice", -1)

	// Another person is unaffected: the ceiling is per subject, not global.
	if n := srv.addForSubject("bob", 1); n != 1 {
		t.Fatalf("bob's first session counted as %d, so the ceiling is shared", n)
	}
}

/** A subject that closes everything is forgotten, rather than left as a zero entry for ever. */
func TestPerSubjectCountsAreForgottenWhenTheyReachZero(t *testing.T) {
	srv := &Server{MaxPerSubject: 3}
	srv.addForSubject("alice", 1)
	srv.addForSubject("alice", -1)

	srv.openMu.Lock()
	_, present := srv.perSubject["alice"]
	srv.openMu.Unlock()
	if present {
		t.Fatal("a subject with no sessions is still in the map, which is a slow leak on a cluster with staff turnover")
	}
}

/*
A TRANSIENT APISERVER FAULT MUST NOT BURN THE PASS FOR EVER.

Before this, one 503 burnt the pass in this process's memory while creating NO Lease. The next
attempt with the same pass was told "already used", which is a lie: nothing durable was written, and
the same pass presented to a second replica would have opened a session. The person retrying is told
the one thing that makes them stop retrying.

Only an UNCONFIRMED claim gives the entry back. A confirmed replay must stay burnt.
*/
type scriptedClaimer struct {
	results []error
	calls   int
}

func (s *scriptedClaimer) Claim(_ context.Context, _ string, _ time.Time) error {
	i := s.calls
	s.calls++
	if i < len(s.results) {
		return s.results[i]
	}
	return nil
}

func TestAnUnconfirmedClaimIsNotRememberedAsSpent(t *testing.T) {
	claimer := &scriptedClaimer{results: []error{replay.ErrUnavailable, nil}}
	srv := &Server{Memory: replay.NewMemory(), Claimer: claimer}
	p := &pass.Payload{JTI: "0123456789abcdef0123456789abcdef", EXP: json.RawMessage("99999999999")}

	if err := srv.claim(context.Background(), p); !errors.Is(err, replay.ErrUnavailable) {
		t.Fatalf("first attempt: expected unavailable, got %v", err)
	}
	// THE RETRY MUST REACH THE APISERVER AGAIN, not be answered from memory.
	if err := srv.claim(context.Background(), p); err != nil {
		t.Fatalf("the retry after a transient fault must be allowed to try again, got %v", err)
	}
	if claimer.calls != 2 {
		t.Fatalf("the durable claim was attempted %d time(s); the retry never reached it", claimer.calls)
	}
}

func TestAConfirmedReplayStaysBurnt(t *testing.T) {
	claimer := &scriptedClaimer{results: []error{nil}}
	srv := &Server{Memory: replay.NewMemory(), Claimer: claimer}
	p := &pass.Payload{JTI: "0123456789abcdef0123456789abcdef", EXP: json.RawMessage("99999999999")}

	if err := srv.claim(context.Background(), p); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := srv.claim(context.Background(), p); !errors.Is(err, replay.ErrReplayed) {
		t.Fatalf("the second use must be refused as replayed, got %v", err)
	}
	// Answered from memory without troubling the apiserver, which is what the layer is for.
	if claimer.calls != 1 {
		t.Fatalf("the durable claim was called %d times; the memory layer is not doing its job", claimer.calls)
	}
}

/** And a durable AlreadyExists must also stay burnt, not be forgotten as if it were a fault. */
func TestADurableReplayIsNotForgotten(t *testing.T) {
	claimer := &scriptedClaimer{results: []error{replay.ErrReplayed, nil}}
	srv := &Server{Memory: replay.NewMemory(), Claimer: claimer}
	p := &pass.Payload{JTI: "0123456789abcdef0123456789abcdef", EXP: json.RawMessage("99999999999")}

	if err := srv.claim(context.Background(), p); !errors.Is(err, replay.ErrReplayed) {
		t.Fatalf("expected replayed, got %v", err)
	}
	if err := srv.claim(context.Background(), p); !errors.Is(err, replay.ErrReplayed) {
		t.Fatalf("a pass the apiserver called spent must stay spent here, got %v", err)
	}
	if claimer.calls != 1 {
		t.Fatalf("the durable claim was called %d times after a confirmed replay", claimer.calls)
	}
}

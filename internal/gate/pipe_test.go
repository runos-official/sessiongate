package gate

import (
	"context"
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

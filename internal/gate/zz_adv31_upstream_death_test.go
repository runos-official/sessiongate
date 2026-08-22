package gate

// ADVERSARIAL SCRATCH. Does a far end that DIES (pod deleted / VM deleted) leave the client's
// session open, as the "no revocation" claim asserts, or does the gate end it?

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestAdvUpstreamKilledEndsTheClientSession drops the upstream TCP with no close frame, which is
// what a deleted VM or a deleted workspace pod looks like from the gate.
func TestAdvUpstreamKilledEndsTheClientSession(t *testing.T) {
	raw := make(chan net.Conn, 1)
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		// Hand the underlying conn out so the test can kill it without a close frame.
		_ = c
		hj, _ := w.(http.Hijacker)
		_ = hj
		go func() {
			time.Sleep(300 * time.Millisecond)
			c.CloseNow() // CloseNow = drop the TCP, no close frame. The pod-died shape.
			raw <- nil
		}()
		<-r.Context().Done()
	}))
	defer upstreamSrv.Close()

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

	start := time.Now()
	_, _, err := client.Read(ctx)
	took := time.Since(start)
	if err == nil {
		t.Fatal("the client read succeeded after the far end died")
	}
	if ctx.Err() != nil {
		t.Fatalf("THE SESSION SURVIVED THE FAR END'S DEATH: still open after %v", took)
	}
	t.Logf("far end died; client session ended after %v with: %v (close status %d)",
		took, err, websocket.CloseStatus(err))
}

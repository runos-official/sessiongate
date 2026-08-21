package gate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/coder/websocket"
	"github.com/runos-official/sessiongate/internal/kubevirt"
	"github.com/runos-official/sessiongate/internal/pass"
	"github.com/runos-official/sessiongate/internal/workspace"
)

// Upstream dials the far end of a session.
type Upstream struct {
	// APIHost is host:port of the Kubernetes apiserver, from the standard in-cluster environment.
	APIHost string
	// Token is read FRESH per dial, because a projected service account token is rotated in place
	// and a token cached at startup stops working an hour later, in a way that looks like the
	// cluster broke rather than like a stale read.
	Token func() (string, error)
	// TLS trusts the cluster CA and pins the apiserver's name.
	TLS *tls.Config
	// HTTP is used for the websocket handshake to the apiserver.
	HTTP *http.Client
	// Now is injectable for tests.
	Now func() time.Time
}

// workspaceProtocol is what runostty selects. It must be offered or the handshake fails with
// "server sent no subprotocol".
const workspaceProtocol = "runos.tty.v1"

// DialTimeout bounds reaching the far end. A VM whose virt-handler is wedged must not hold a client
// waiting indefinitely with no close code.
const DialTimeout = 15 * time.Second

// InClusterUpstream builds an Upstream from the standard service-account mount.
func InClusterUpstream() (*Upstream, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST and _PORT are unset: this must run in a cluster")
	}
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("reading the cluster CA at %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("the cluster CA at %s is not a PEM certificate", caPath)
	}
	tlsConfig := &tls.Config{
		RootCAs: pool,
		// The apiserver's certificate names kubernetes.default.svc, not the service IP the
		// environment gives us, so the name is pinned explicitly rather than the verification
		// being turned off. InsecureSkipVerify here would mean any pod that can win a race for the
		// service IP could read every session on the cluster.
		ServerName: "kubernetes.default.svc",
		MinVersion: tls.VersionTLS12,
	}
	return &Upstream{
		APIHost: host + ":" + port,
		Token:   readTokenFresh,
		TLS:     tlsConfig,
		HTTP:    &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		Now:     time.Now,
	}, nil
}

var tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func readTokenFresh() (string, error) {
	b, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DialVM opens the KubeVirt subresource for a verified VM pass.
func (u *Upstream) DialVM(ctx context.Context, p *pass.Payload) (*websocket.Conn, error) {
	target, err := kubevirt.Resolve(p)
	if err != nil {
		return nil, err
	}
	dialURL := target.URL(u.APIHost)

	// THE LAST LINE OF DEFENCE, on the bytes actually going out, after every transformation. See
	// kubevirt.AssertSSHPortPinned: this panics rather than returning an error, because an error is
	// what a later edit logs and continues past, and the failure it guards is silent by nature.
	kubevirt.AssertSSHPortPinned(p.Kind, dialURL)

	token, err := u.Token()
	if err != nil {
		return nil, fmt.Errorf("reading the service account token: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()

	conn, res, err := websocket.Dial(ctx, dialURL, &websocket.DialOptions{
		HTTPClient: u.HTTP,
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
		// No subprotocols. KubeVirt's stream endpoints negotiate none, and offering one it does not
		// know is a handshake failure rather than a graceful fallback.
	})
	if err != nil {
		if res != nil {
			return nil, fmt.Errorf("the cluster refused the session (%d): %w", res.StatusCode, err)
		}
		return nil, err
	}
	// KubeVirt streams a whole VNC framebuffer through this, which is comfortably past the 32 KiB
	// default. A limit that is too small looks exactly like a corrupted screen.
	conn.SetReadLimit(32 << 20)
	return conn, nil
}

// DialWorkspace opens the terminal endpoint of a workspace pod.
//
// THE PASS IS FORWARDED, and the workspace verifies it again. That is not ceremony: the workspace is
// the only party that knows whose workspace it is, so it is the only party that can check the pass
// was minted for THIS one. The alternative would be a shared secret the gate has to read, which
// means giving the gate permission to read Secrets, and a component that can read one can read them
// all.
//
// Nothing about the session travels in the URL. The user, the working directory and the command all
// come from the signed bytes at the far end, so anything that could reach port 7681 directly still
// cannot choose them.
func (u *Upstream) DialWorkspace(ctx context.Context, p *pass.Payload, token string) (*websocket.Conn, error) {
	target, err := workspace.Resolve(p)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()

	// Plain ws:// inside the cluster: the hop is pod to pod inside the CNI, the workspace serves
	// plain HTTP on 7681, and a network policy is what keeps anything else off that port.
	conn, res, err := websocket.Dial(ctx, target.URL("ws", "/"), &websocket.DialOptions{
		// The workspace answers with the plain protocol name and never echoes the pass, exactly as
		// this gate does for its own clients.
		Subprotocols: []string{workspaceProtocol, PassProtocolPrefix + token},
	})
	if err != nil {
		if res != nil {
			return nil, fmt.Errorf("the workspace refused the session (%d): %w", res.StatusCode, err)
		}
		return nil, err
	}
	conn.SetReadLimit(32 << 20)
	return conn, nil
}

/*
Pipe copies bytes both ways until either side stops, and ends the OTHER side cleanly.

MEASURED 2026-08-21, and this cost a real client a wrong error message. The first version gave both
directions a derived, cancellable context and cancelled it to unblock the other goroutine. In
coder/websocket a read whose context is cancelled CLOSES THE CONNECTION ABRUPTLY: the TCP goes away
with no close frame. The CLI, correctly, refuses to treat a frameless drop as a clean ending, because
that is exactly what a broken session looks like, so a perfectly normal one-shot ended with

	Error: failed to get reader: failed to read frame header: EOF

A gate that cannot end a session cleanly makes every client either wrong about failures or wrong
about successes.

So: reads use the REQUEST's context and are never cancelled to control flow. When one direction ends,
the other connection is CLOSED WITH A STATUS, which makes its blocked read return a proper close
error, and the status is carried across so a normal close stays a normal close.
*/
func Pipe(ctx context.Context, client, upstream *websocket.Conn) error {
	type ending struct {
		err  error
		from string
	}
	done := make(chan ending, 2)

	copyOneWay := func(dst, src *websocket.Conn, from string) {
		for {
			typ, data, err := src.Read(ctx)
			if err != nil {
				// Carry the peer's own ending across rather than inventing one. A far end that said
				// "normal closure" must not reach the client as an abnormal drop.
				dst.Close(closeStatusFor(err), "")
				done <- ending{err: err, from: from}
				return
			}
			if err := dst.Write(ctx, typ, data); err != nil {
				src.Close(closeStatusFor(err), "")
				done <- ending{err: err, from: from}
				return
			}
		}
	}

	go copyOneWay(upstream, client, "client")
	go copyOneWay(client, upstream, "upstream")

	first := <-done
	// The second goroutine is unblocked by the close above. Waiting for it is what keeps a
	// half-pipe from outliving the session and leaking a goroutine per connection.
	<-done
	return first.err
}

/*
closeStatusFor turns one side's ending into the status to close the other side with.

A close frame the peer sent is reused as-is. Anything else, including a frameless drop, becomes
"going away", which is honest: this end is finishing and the reason was not stated in a frame.
Inventing a normal closure for a broken connection is the mistake that makes a client report success
for a session that died.
*/
func closeStatusFor(err error) websocket.StatusCode {
	if status := websocket.CloseStatus(err); status != -1 {
		if status == websocket.StatusNoStatusRcvd || status == websocket.StatusAbnormalClosure {
			return websocket.StatusNormalClosure
		}
		return status
	}
	return websocket.StatusGoingAway
}

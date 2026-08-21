package gate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
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

// Pipe copies bytes both ways until either side stops, and returns the first error that mattered.
//
// A PORT OF conductor/src/api/websocket/vmConsolePipe.ts, and the behaviour it pins is worth
// stating: whichever side closes first, the other is closed too, and neither goroutine is left
// holding a connection nobody reads. A leaked half-pipe is how a gate accumulates goroutines until
// it dies of something that looks unrelated.
func Pipe(ctx context.Context, client, upstream *websocket.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var once sync.Once
	var first error
	done := make(chan struct{}, 2)

	copyOneWay := func(dst, src *websocket.Conn) {
		defer func() { done <- struct{}{} }()
		for {
			typ, data, err := src.Read(ctx)
			if err != nil {
				once.Do(func() { first = err })
				cancel()
				return
			}
			if err := dst.Write(ctx, typ, data); err != nil {
				once.Do(func() { first = err })
				cancel()
				return
			}
		}
	}

	go copyOneWay(upstream, client)
	go copyOneWay(client, upstream)

	<-done
	// The second goroutine is unblocked by the cancel above; waiting for it here is what keeps a
	// half-pipe from outliving the session.
	<-done
	return first
}

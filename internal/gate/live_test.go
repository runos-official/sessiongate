package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/runos-official/sessiongate/internal/pass"
)

/*
LIVE tests against a real gate on a real cluster.

Skipped unless RUNOS_GATE_LIVE_URL is set, so an ordinary `go test ./...` stays hermetic. This file
exists because the unit tests cannot see the things that actually break: RBAC that is subtly wrong,
a KubeVirt subprotocol nobody wrote down, a Lease the apiserver refuses for a reason the fake never
produced, a token path that differs in the real image.

Run it with:

	RUNOS_GATE_LIVE_URL=ws://127.0.0.1:18080 \
	RUNOS_GATE_LIVE_KEY=/tmp/gatekey.json \
	RUNOS_GATE_LIVE_VM=vmgroup-xxxxx/vm-name \
	go test ./internal/gate -run TestLive -v -count=1

where the key file is {"kid","pem"} for the key the gate was given.
*/

type liveKey struct {
	KID string `json:"kid"`
	PEM string `json:"pem"`
}

func liveHarness(t *testing.T) (string, ed25519.PrivateKey, string, string) {
	t.Helper()
	base := os.Getenv("RUNOS_GATE_LIVE_URL")
	if base == "" {
		t.Skip("set RUNOS_GATE_LIVE_URL to run the live tests")
	}
	raw, err := os.ReadFile(os.Getenv("RUNOS_GATE_LIVE_KEY"))
	if err != nil {
		t.Fatalf("RUNOS_GATE_LIVE_KEY: %v", err)
	}
	var k liveKey
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(k.PEM))
	if block == nil {
		t.Fatal("the key file does not hold a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("the key is %T, not Ed25519", parsed)
	}
	target := os.Getenv("RUNOS_GATE_LIVE_VM")
	ns, name, _ := strings.Cut(target, "/")
	return base, priv, ns, name
}

func livePass(t *testing.T, key ed25519.PrivateKey, kid string, mutate func(*pass.Payload)) string {
	t.Helper()
	now := time.Now().Unix()
	p := &pass.Payload{
		V: 1, JTI: randomJTI(t),
		IAT: json.RawMessage(fmt.Sprintf("%d", now)),
		EXP: json.RawMessage(fmt.Sprintf("%d", now+60)),
		AID: "rjwrn", CID: "v6b", Sub: "live-test", Kind: pass.KindVMSerial,
		Org: "https://console.runos.com",
	}
	if mutate != nil {
		mutate(p)
	}
	token, err := pass.Sign(p, kid, key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func randomJTI(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	f, err := os.Open("/dev/urandom")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

func liveKID(t *testing.T) string {
	t.Helper()
	raw, _ := os.ReadFile(os.Getenv("RUNOS_GATE_LIVE_KEY"))
	var k liveKey
	_ = json.Unmarshal(raw, &k)
	return k.KID
}

func dialGate(ctx context.Context, base, token string) (*websocket.Conn, *websocketResponse, error) {
	conn, res, err := websocket.Dial(ctx, base+"/v1/session", &websocket.DialOptions{
		Subprotocols: []string{SessionProtocol, PassProtocolPrefix + token},
	})
	wrapped := &websocketResponse{}
	if res != nil {
		wrapped.Status = res.StatusCode
	}
	return conn, wrapped, err
}

type websocketResponse struct{ Status int }

/** A real VM serial console, through the real gate, over the real apiserver. */
func TestLiveSerialConsole(t *testing.T) {
	base, key, ns, name := liveHarness(t)
	if ns == "" || name == "" {
		t.Skip("set RUNOS_GATE_LIVE_VM to vmgroup-xxxxx/vm-name")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindVMSerial
		p.VM = &pass.VMTarget{Namespace: ns, Name: name}
	})
	conn, res, err := dialGate(ctx, base, token)
	if err != nil {
		t.Fatalf("the gate refused a valid serial pass (http %d): %v", res.Status, err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	if got := conn.Subprotocol(); got != SessionProtocol {
		t.Errorf("negotiated %q, want %q: the gate must never echo the pass", got, SessionProtocol)
	}

	// A newline wakes a login prompt on a serial console that has gone quiet.
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	readCtx, readCancel := context.WithTimeout(ctx, 20*time.Second)
	defer readCancel()
	_, data, err := conn.Read(readCtx)
	if err != nil {
		t.Fatalf("the session opened but the guest sent nothing: %v", err)
	}
	t.Logf("guest sent %d bytes: %q", len(data), truncate(string(data), 120))
}

/** The same pass twice. The second must be refused as spent, by the Lease. */
func TestLiveReplayIsRefused(t *testing.T) {
	base, key, ns, name := liveHarness(t)
	if ns == "" {
		t.Skip("set RUNOS_GATE_LIVE_VM")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindVMSerial
		p.VM = &pass.VMTarget{Namespace: ns, Name: name}
	})

	first, _, err := dialGate(ctx, base, token)
	if err != nil {
		t.Fatalf("the first use must succeed: %v", err)
	}
	first.Close(websocket.StatusNormalClosure, "")

	second, _, err := dialGate(ctx, base, token)
	if err != nil {
		t.Fatalf("the second use must complete a handshake and then close, not fail the dial: %v", err)
	}
	defer second.Close(websocket.StatusNormalClosure, "")
	_, _, readErr := second.Read(ctx)
	if code := websocket.CloseStatus(readErr); int(code) != CloseReplayed {
		t.Fatalf("replay closed with %d, want %d", code, CloseReplayed)
	}
}

/** A pass for another cluster is refused with a code a client can act on. */
func TestLiveWrongClusterIsRefused(t *testing.T) {
	base, key, ns, name := liveHarness(t)
	if ns == "" {
		t.Skip("set RUNOS_GATE_LIVE_VM")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.CID = "zzz"
		p.Kind = pass.KindVMSerial
		p.VM = &pass.VMTarget{Namespace: ns, Name: name}
	})
	conn, _, err := dialGate(ctx, base, token)
	if err != nil {
		t.Fatalf("expected a handshake then a close: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	_, _, readErr := conn.Read(ctx)
	if code := websocket.CloseStatus(readErr); int(code) != CloseWrongCluster {
		t.Fatalf("closed with %d, want %d", code, CloseWrongCluster)
	}
}

/** An unsigned or tampered pass is refused, and every cause looks the same to the client. */
func TestLiveForgedPassIsRefused(t *testing.T) {
	base, _, _, _ := liveHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	other := ed25519.NewKeyFromSeed([]byte("not-the-clusters-key-000000000001"[:32]))
	token := livePass(t, other, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindVMSerial
		p.VM = &pass.VMTarget{Namespace: "vmgroup-aaaaa", Name: "vm-aaaaa"}
	})
	conn, _, err := dialGate(ctx, base, token)
	if err != nil {
		t.Fatalf("expected a handshake then a close: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	_, _, readErr := conn.Read(ctx)
	if code := websocket.CloseStatus(readErr); int(code) != ClosePassRefused {
		t.Fatalf("closed with %d, want %d", code, ClosePassRefused)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

/*
THE PORT-FORWARD PATH, live, against a real guest.

This is the path where losing one literal turns a console into a general TCP tunnel, so it is worth
proving against a real sshd rather than only in a fuzz test. KubeVirt's portforward subresource is a
raw byte stream, so a working session means the guest's SSH banner arrives unchanged.
*/
func TestLiveSSHPortForwardReachesTheGuestSSHD(t *testing.T) {
	base, key, ns, name := liveHarness(t)
	if ns == "" {
		t.Skip("set RUNOS_GATE_LIVE_VM")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindVMSSH
		p.VM = &pass.VMTarget{Namespace: ns, Name: name}
	})
	conn, res, err := dialGate(ctx, base, token)
	if err != nil {
		t.Fatalf("the gate refused a valid vm.ssh pass (http %d): %v", res.Status, err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	readCtx, readCancel := context.WithTimeout(ctx, 25*time.Second)
	defer readCancel()
	_, banner, err := conn.Read(readCtx)
	if err != nil {
		t.Fatalf("the port-forward opened but the guest sent nothing: %v", err)
	}
	// An SSH server speaks first. Anything else means the stream reached something that is not sshd,
	// which is exactly what the port pin exists to prevent.
	if !strings.HasPrefix(string(banner), "SSH-2.0-") {
		t.Fatalf("expected an SSH banner, the guest sent %q", truncate(string(banner), 80))
	}
	t.Logf("guest sshd said: %q", strings.TrimSpace(string(banner)))
}

/*
THE WORKSPACE TERMINAL, live, end to end: client -> gate -> workspace.

The pass is verified TWICE on this path, by two programs written in two languages: the gate admits
it, and the workspace confirms it was minted for THAT workspace. Only the workspace knows whose it
is, which is why the second check exists and why it cannot be replaced by a network policy.

Needs RUNOS_GATE_LIVE_WS=svc/uid naming the workspace and its declared owner.
*/
func TestLiveWorkspaceTerminal(t *testing.T) {
	base, key, _, _ := liveHarness(t)
	svc, uid, ok := strings.Cut(os.Getenv("RUNOS_GATE_LIVE_WS"), "/")
	if !ok {
		t.Skip("set RUNOS_GATE_LIVE_WS to svc/uid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindWSTerminal
		p.Sub = uid
		p.WS = &pass.WSTarget{Service: svc, UID: uid, User: "devops", Dir: "", Cmd: ""}
	})
	conn, res, err := dialGate(ctx, base, token)
	if err != nil {
		t.Fatalf("the gate refused a valid workspace pass (http %d): %v", res.Status, err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// A shell prints a prompt without being asked. Reading anything at all proves the whole chain:
	// the gate verified, claimed and dialled, and the workspace verified the forwarded pass and
	// spawned a PTY.
	readCtx, readCancel := context.WithTimeout(ctx, 25*time.Second)
	defer readCancel()
	_, data, err := conn.Read(readCtx)
	if err != nil {
		t.Fatalf("the terminal opened but said nothing: %v", err)
	}
	t.Logf("workspace shell said: %q", truncate(string(data), 120))
}

/*
A VALID PASS FOR ANOTHER WORKSPACE MUST NOT OPEN THIS ONE.

This is the check that only the workspace can make, and the reason the pass travels the extra hop.
The gate happily routes it, because the gate's job is to admit a well-formed pass and dial what it
names; the workspace is what refuses.
*/
func TestLiveWorkspaceRefusesAPassForAnotherWorkspace(t *testing.T) {
	base, key, _, _ := liveHarness(t)
	svc, _, ok := strings.Cut(os.Getenv("RUNOS_GATE_LIVE_WS"), "/")
	if !ok {
		t.Skip("set RUNOS_GATE_LIVE_WS")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	/*
	 * SELF-VALIDATING, and it has to be.
	 *
	 * The first version of this test passed against a gate that forwarded NO pass at all: the
	 * workspace refused with "no session pass was offered" and the test read that as "refused the
	 * foreign owner". A negative test that passes when the mechanism is entirely missing is worse
	 * than no test, because it reports the property as held.
	 *
	 * So it proves the positive case FIRST, in the same run. If forwarding is broken, this fails
	 * here rather than passing below for the wrong reason.
	 */
	good := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindWSTerminal
		p.Sub = os.Getenv("RUNOS_GATE_LIVE_WS")[strings.Index(os.Getenv("RUNOS_GATE_LIVE_WS"), "/")+1:]
		p.WS = &pass.WSTarget{Service: svc, UID: p.Sub, User: "devops"}
	})
	proof, _, err := dialGate(ctx, base, good)
	if err != nil {
		t.Fatalf("the owner's own pass must open a session, or this test cannot tell a refused "+
			"owner from a gate that forwards nothing: %v", err)
	}
	proofCtx, proofCancel := context.WithTimeout(ctx, 15*time.Second)
	defer proofCancel()
	if _, _, err := proof.Read(proofCtx); err != nil {
		proof.Close(websocket.StatusNormalClosure, "")
		t.Fatalf("the owner's own session opened but said nothing, so the negative case below would "+
			"prove nothing: %v", err)
	}
	proof.Close(websocket.StatusNormalClosure, "")

	// Signed, fresh, correct cluster, correct kind: everything a gate checks. The owner is someone
	// else, which only the workspace can know.
	token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindWSTerminal
		p.Sub = "SomeoneElse000000000000000001"
		p.WS = &pass.WSTarget{Service: svc, UID: "SomeoneElse000000000000000001", User: "devops"}
	})
	conn, _, err := dialGate(ctx, base, token)
	if err != nil {
		// The gate dialled and the workspace refused the upgrade, which surfaces as a failed dial
		// at the gate and a 4502 to us. Either shape is a refusal; what must NOT happen is a shell.
		t.Logf("refused at dial, as expected: %v", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	readCtx, readCancel := context.WithTimeout(ctx, 10*time.Second)
	defer readCancel()
	_, data, readErr := conn.Read(readCtx)
	if readErr == nil {
		t.Fatalf("a pass for ANOTHER owner opened a shell here and it said %q", truncate(string(data), 80))
	}
	t.Logf("refused after handshake, as expected: %v", readErr)
}

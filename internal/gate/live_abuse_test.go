package gate

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/runos-official/sessiongate/internal/pass"
)

/*
ABUSE tests against a live gate. Skipped unless RUNOS_GATE_LIVE_URL is set.

These are deliberately not tidy unit tests. They do the things a unit test cannot: race a real
apiserver, throw malformed bytes at a real listener, and hold a real session open. Every one of them
exists because the property it checks is one a fake would confirm regardless.
*/

/*
FIFTY SIMULTANEOUS USES OF ONE PASS. Exactly one may open a session.

The in-process set answers most of these without a round trip, so this also exercises the case the
Lease exists for: the memory layer is per-process and knows nothing after a restart or on a second
replica. What must never happen is two sessions from one pass.
*/
func TestLiveOnePassOpensExactlyOneSession(t *testing.T) {
	base, key, ns, name := liveHarness(t)
	if ns == "" {
		t.Skip("set RUNOS_GATE_LIVE_VM")
	}
	token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindVMSerial
		p.VM = &pass.VMTarget{Namespace: ns, Name: name}
	})

	const racers = 50
	var opened, replayed, other atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // all of them at once, as close as the scheduler allows
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, _, err := dialGate(ctx, base, token)
			if err != nil {
				other.Add(1)
				return
			}
			defer conn.Close(websocket.StatusNormalClosure, "")
			// A newline first, because a serial console says nothing unprompted. Without it the ONE
			// winner blocks on read until the context expires and is counted as "other", which makes
			// the result ambiguous exactly where it needs to be sharp: the test cannot tell "one
			// session opened" from "none did".
			_ = conn.Write(ctx, websocket.MessageBinary, []byte("\r\n"))
			// A refusal arrives as a close code after the handshake, so read to find out.
			readCtx, readCancel := context.WithTimeout(ctx, 15*time.Second)
			defer readCancel()
			_, _, readErr := conn.Read(readCtx)
			switch code := websocket.CloseStatus(readErr); {
			case readErr == nil:
				opened.Add(1)
			case int(code) == CloseReplayed:
				replayed.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	t.Logf("of %d simultaneous uses: %d opened, %d refused as replayed, %d other",
		racers, opened.Load(), replayed.Load(), other.Load())
	if opened.Load() > 1 {
		t.Fatalf("ONE PASS OPENED %d SESSIONS. Single use is not single use.", opened.Load())
	}
	if replayed.Load() == 0 {
		t.Fatalf("no attempt was refused as replayed, so nothing proves the claim ran at all")
	}
	// EXACTLY ONE, not "at most one". A run where nothing opened would pass an at-most assertion
	// while proving only that the gate refuses everything, which is not the property under test.
	if opened.Load() != 1 {
		t.Fatalf("expected exactly 1 session to open, %d did (%d replayed, %d other)",
			opened.Load(), replayed.Load(), other.Load())
	}
}

/*
MALFORMED BYTES AT A REAL LISTENER.

Every one of these must be refused, none may open a session, and NONE may take the gate down. The
last part is why this runs against the live pod: a panic in a handler is a unit test away from
looking fine and a production incident away from being obvious.
*/
func TestLiveGarbageIsRefusedAndTheGateSurvives(t *testing.T) {
	base, key, _, _ := liveHarness(t)
	valid := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindVMSerial
		p.VM = &pass.VMTarget{Namespace: "vmgroup-aaaaa", Name: "vm-aaaaa"}
	})
	parts := strings.SplitN(valid, ".", 3)

	garbage := []string{
		"",
		".",
		"..",
		"runos_pass_v1",
		"runos_pass_v1.",
		"runos_pass_v1..",
		"runos_pass_v1..AAAA",
		"runos_pass_v2." + parts[1] + "." + parts[2],
		"runos_pass_v1." + parts[1] + "." + parts[2] + ".extra",
		"runos_pass_v1." + parts[1] + "." + parts[2] + "\r\n",
		" " + valid,
		valid + " ",
		strings.ToUpper(valid),
		"runos_pass_v1." + strings.Repeat("A", 3000) + ".AAAA",
		"runos_pass_v1.eyJ2IjoxfQ.AAAA",
		"runos_pass_v1." + parts[1] + ".AAAA",
		"\x00\x01\x02",
		"runos_pass_v1.\x00.\x00",
	}

	for i, token := range garbage {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		conn, _, err := dialGate(ctx, base, token)
		if err != nil {
			cancel()
			continue // refused before or during the handshake, which is a refusal
		}
		_, _, readErr := conn.Read(ctx)
		if readErr == nil {
			conn.Close(websocket.StatusNormalClosure, "")
			cancel()
			t.Fatalf("garbage #%d OPENED A SESSION: %q", i, truncate(token, 60))
		}
		conn.Close(websocket.StatusNormalClosure, "")
		cancel()
	}

	// THE GATE MUST STILL BE THERE. A refusal that takes the process with it is worse than an
	// acceptance, because it takes every other session too.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	after := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindVMSerial
		p.VM = &pass.VMTarget{Namespace: "vmgroup-aaaaa", Name: "vm-aaaaa"}
	})
	if _, _, err := dialGate(ctx, base, after); err != nil {
		t.Fatalf("the gate stopped answering after %d malformed passes: %v", len(garbage), err)
	}
}

/*
AN ORIGIN THE GATE DOES NOT ACCEPT, presented to the live listener.

The browser cases matter because a browser always sends Origin and cannot suppress it, so this is
the check that stands between a hostile page and someone's session.
*/
func TestLiveHostileOriginsAreRefused(t *testing.T) {
	base, key, ns, name := liveHarness(t)
	if ns == "" {
		t.Skip("set RUNOS_GATE_LIVE_VM")
	}
	for _, origin := range []string{
		"https://evil.test",
		"https://console.dev.runos.com.evil.test",
		"https://evil-console.dev.runos.com",
		"http://console.dev.runos.com",
		"null",
	} {
		token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
			p.Kind = pass.KindVMSerial
			p.VM = &pass.VMTarget{Namespace: ns, Name: name}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		conn, _, err := websocket.Dial(ctx, base+"/v1/session", &websocket.DialOptions{
			Subprotocols: []string{SessionProtocol, PassProtocolPrefix + token},
			HTTPHeader:   map[string][]string{"Origin": {origin}},
		})
		if err != nil {
			cancel()
			continue
		}
		_, _, readErr := conn.Read(ctx)
		opened := readErr == nil
		conn.Close(websocket.StatusNormalClosure, "")
		cancel()
		if opened {
			t.Errorf("origin %q opened a session", origin)
		}
	}
}

/*
A SESSION HELD OPEN, with traffic, for a while.

Not a load test. It exists because the failure it looks for is invisible in a short test: an idle
timeout somewhere in the chain, a proxy that drops a quiet connection, a read limit that only bites
after enough bytes.
*/
func TestLiveSessionSurvivesSustainedTraffic(t *testing.T) {
	base, key, ns, name := liveHarness(t)
	if ns == "" {
		t.Skip("set RUNOS_GATE_LIVE_VM")
	}
	seconds := 30
	if v := os.Getenv("RUNOS_GATE_LIVE_SECONDS"); v != "" {
		fmt.Sscanf(v, "%d", &seconds)
	}

	token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindVMSerial
		p.VM = &pass.VMTarget{Namespace: ns, Name: name}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+60)*time.Second)
	defer cancel()

	conn, _, err := dialGate(ctx, base, token)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	bytesIn := 0
	for time.Now().Before(deadline) {
		if err := conn.Write(ctx, websocket.MessageBinary, []byte("\r\n")); err != nil {
			t.Fatalf("the session died after %d bytes: %v", bytesIn, err)
		}
		readCtx, readCancel := context.WithTimeout(ctx, 10*time.Second)
		_, data, err := conn.Read(readCtx)
		readCancel()
		if err != nil {
			t.Fatalf("the session died after %d bytes: %v", bytesIn, err)
		}
		bytesIn += len(data)
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("held a session for %ds, %d bytes back, still alive", seconds, bytesIn)
}

// unused import guard
var _ = json.Marshal
var _ = ed25519.PublicKeySize

/*
KILL THE GATE MID-SESSION.

A gate restart drops every live session on the cluster, which is a known and accepted cost of the
design. What matters is HOW it drops them: a client must be able to tell "the gate went away, mint
another pass and reconnect" from "your pass was refused" and from "the machine is gone". A frameless
drop tells it none of those.

Needs kubectl reachable and RUNOS_GATE_LIVE_KILL set to the deployment to restart, e.g.
"runos/runos-session-gate".
*/
func TestLiveClientLearnsWhyWhenTheGateGoesAway(t *testing.T) {
	base, key, ns, name := liveHarness(t)
	target := os.Getenv("RUNOS_GATE_LIVE_KILL")
	if ns == "" || target == "" {
		t.Skip("set RUNOS_GATE_LIVE_VM and RUNOS_GATE_LIVE_KILL=namespace/deployment")
	}
	namespace, deployment, _ := strings.Cut(target, "/")

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	token := livePass(t, key, liveKID(t), func(p *pass.Payload) {
		p.Kind = pass.KindVMSerial
		p.VM = &pass.VMTarget{Namespace: ns, Name: name}
	})
	conn, _, err := dialGate(ctx, base, token)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Prove the session is live before taking anything away, or a failure below proves nothing.
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	readCtx, readCancel := context.WithTimeout(ctx, 20*time.Second)
	_, _, err = conn.Read(readCtx)
	readCancel()
	if err != nil {
		t.Fatalf("the session was not live before the restart: %v", err)
	}

	restart := exec.Command("kubectl", "rollout", "restart", "-n", namespace, "deploy/"+deployment)
	if out, err := restart.CombinedOutput(); err != nil {
		t.Fatalf("could not restart the gate: %v: %s", err, out)
	}
	t.Log("gate restarted, waiting for the session to end")

	// Long enough to outlast the gate's drain window, which is 240s by default and set shorter on a
	// lab cluster. A test that gives up before the drain does proves nothing about the ending.
	endCtx, endCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer endCancel()
	for {
		_, _, err = conn.Read(endCtx)
		if err != nil {
			break
		}
	}

	status := websocket.CloseStatus(err)
	t.Logf("the session ended with close status %d (%v)", status, err)
	// The gate drains rather than cutting, so a session may well survive its own pod's replacement
	// and end only when the old pod finally stops. Either ending is acceptable; what is NOT is a
	// frameless drop, which a client cannot tell from a dead cluster.
	if status == -1 {
		t.Fatalf("the session ended with NO close frame, so a client cannot tell a restarting gate "+
			"from a dead one: %v", err)
	}
	// 4001 is the one that tells a client to mint a new pass and reconnect. A normal closure would
	// be honest but less useful; anything else would be wrong.
	if int(status) != CloseDraining && status != websocket.StatusNormalClosure {
		t.Errorf("closed with %d; a draining gate should say %d so a client knows to reconnect",
			status, CloseDraining)
	}
}

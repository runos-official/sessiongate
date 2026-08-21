package gate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runos-official/sessiongate/internal/pass"
)

// The gate's tests sign their own passes with the same test key the golden vectors use, so a change
// to the wire format breaks both together rather than leaving this suite passing against a format
// nothing else speaks.
func harness(t *testing.T) (ed25519.PrivateKey, Config, func() time.Time) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "pass", "testdata", "passes.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf struct {
		KID         string `json:"kid"`
		PublicKey   string `json:"publicKeyB64url"`
		PrivateSeed string `json:"privateKeySeedB64url"`
		NowUnix     int64  `json:"nowUnix"`
	}
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	seed, _ := base64.RawURLEncoding.DecodeString(vf.PrivateSeed)
	pub, _ := base64.RawURLEncoding.DecodeString(vf.PublicKey)
	at := time.Unix(vf.NowUnix, 0).UTC()

	return ed25519.NewKeyFromSeed(seed),
		Config{
			AID: "rjwrn", CID: "v6b",
			Keys:           pass.Keys{vf.KID: ed25519.PublicKey(pub)},
			AllowedOrigins: []string{"https://console.runos.com"},
			Skew:           30 * time.Second,
		},
		func() time.Time { return at }
}

func signVM(t *testing.T, key ed25519.PrivateKey, mutate func(p *pass.Payload)) string {
	t.Helper()
	p := &pass.Payload{
		V: 1, JTI: "0123456789abcdef0123456789abcdef",
		IAT: json.RawMessage("1755800000"), EXP: json.RawMessage("1755800060"),
		AID: "rjwrn", CID: "v6b", Sub: "u1", Kind: pass.KindVMSSH, Org: "https://console.runos.com",
		VM: &pass.VMTarget{Namespace: "vmgroup-a1b2c", Name: "vm-abcde"},
	}
	if mutate != nil {
		mutate(p)
	}
	token, err := pass.Sign(p, "a1b2c3d4e5f60718", key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// signWithKid mints a correctly signed pass naming a key id this gate does not hold, which is what
// a rotation the gate has not seen looks like, and also what someone guessing looks like.
func signWithKid(t *testing.T, key ed25519.PrivateKey, kid string) string {
	t.Helper()
	p := &pass.Payload{
		V: 1, JTI: "0123456789abcdef0123456789abcdef",
		IAT: json.RawMessage("1755800000"), EXP: json.RawMessage("1755800060"),
		AID: "rjwrn", CID: "v6b", Sub: "u1", Kind: pass.KindVMSSH, Org: "https://console.runos.com",
		VM: &pass.VMTarget{Namespace: "vmgroup-a1b2c", Name: "vm-abcde"},
	}
	token, err := pass.Sign(p, kid, key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func sessionRequest(token string) Request {
	return Request{
		Path:         "/v1/session",
		Subprotocols: []string{SessionProtocol, PassProtocolPrefix + token},
		AllowedKinds: []pass.Kind{pass.KindVMSSH, pass.KindVMSerial, pass.KindVMVNC, pass.KindWSTerminal},
	}
}

func TestAllowsAWellFormedSession(t *testing.T) {
	key, cfg, now := harness(t)
	d := Verify(sessionRequest(signVM(t, key, nil)), cfg, now)
	if !d.Allow {
		t.Fatalf("refused: %s / %s", d.ClientText, d.LogReason)
	}
	if d.Payload == nil || d.Payload.Kind != pass.KindVMSSH {
		t.Fatal("the decision must carry the verified payload")
	}
}

/**
 * THE ORACLE TEST, and the reason every 4401 shares one text.
 *
 * Distinct messages for "expired", "bad signature" and "unknown key" tell a prober which guess was
 * closer, which is the whole game when someone is fishing. The operator gets the real cause from the
 * gate's log; the client gets one sentence.
 */
func TestEveryPassRefusalLooksIdenticalToTheClient(t *testing.T) {
	key, cfg, now := harness(t)
	otherKey := ed25519.NewKeyFromSeed([]byte("a-completely-different-key-00001"))

	cases := map[string]string{
		"expired":         signVM(t, key, func(p *pass.Payload) { p.IAT, p.EXP = json.RawMessage("1755000000"), json.RawMessage("1755000060") }),
		"not yet valid":   signVM(t, key, func(p *pass.Payload) { p.IAT, p.EXP = json.RawMessage("1755900000"), json.RawMessage("1755900060") }),
		"wrong key":       signVM(t, otherKey, nil),
		"unknown kid":     signWithKid(t, key, "ffffffffffffffff"),
		"garbage":         "runos_pass_v1.bm90anNvbg.AAAA",
		"wrong prefix":    "runos_pass_vX." + strings.SplitN(signVM(t, key, nil), ".", 3)[1] + ".AAAA",
		"lifetime absurd": signVM(t, key, func(p *pass.Payload) { p.EXP = json.RawMessage("1755886400") }),
	}

	texts := map[string]bool{}
	for name, token := range cases {
		d := Verify(sessionRequest(token), cfg, now)
		if d.Allow {
			t.Fatalf("%s was allowed", name)
		}
		if d.CloseCode != ClosePassRefused {
			t.Errorf("%s: close code %d, want %d", name, d.CloseCode, ClosePassRefused)
		}
		texts[d.ClientText] = true
		// The operator's copy MUST be specific, or the log is as useless as the client message.
		if d.LogReason == "" || d.LogReason == d.ClientText {
			t.Errorf("%s: the log reason must say more than the client text", name)
		}
	}
	if len(texts) != 1 {
		t.Fatalf("the client saw %d different messages; a prober would learn which guess was closer: %v", len(texts), texts)
	}
}

func TestRefusesAPassForAnotherCluster(t *testing.T) {
	key, cfg, now := harness(t)
	for _, mutate := range []func(p *pass.Payload){
		func(p *pass.Payload) { p.CID = "z42" },
		func(p *pass.Payload) { p.AID = "other" },
	} {
		d := Verify(sessionRequest(signVM(t, key, mutate)), cfg, now)
		if d.CloseCode != CloseWrongCluster {
			t.Errorf("close code %d, want %d (%s)", d.CloseCode, CloseWrongCluster, d.LogReason)
		}
	}
}

/**
 * An absent Origin is NOT a hole, and this pins the reasoning.
 *
 * A browser always sends Origin on a WebSocket upgrade and cannot suppress it; the CLI never sends
 * one. Requiring it would break every non-browser client for no gain.
 */
func TestOriginIsCheckedOnlyWhenPresent(t *testing.T) {
	key, cfg, now := harness(t)
	token := signVM(t, key, nil)

	noOrigin := Verify(sessionRequest(token), cfg, now)
	if !noOrigin.Allow {
		t.Fatalf("a CLI client sends no Origin and must be served: %s", noOrigin.LogReason)
	}

	good := sessionRequest(token)
	good.Origin = "https://console.runos.com"
	if d := Verify(good, cfg, now); !d.Allow {
		t.Fatalf("the console origin must be served: %s", d.LogReason)
	}

	for _, bad := range []string{
		"https://evil.test",
		// The classic prefix and suffix bugs. Both contain the allowed origin as a substring.
		"https://console.runos.com.evil.test",
		"https://evil-console.runos.com",
		// Scheme matters: a page served over http is not the console.
		"http://console.runos.com",
		// So does the port.
		"https://console.runos.com:8443",
	} {
		req := sessionRequest(token)
		req.Origin = bad
		d := Verify(req, cfg, now)
		if d.Allow {
			t.Errorf("origin %q was allowed", bad)
		} else if d.CloseCode != CloseWrongCluster {
			t.Errorf("origin %q: close %d, want %d", bad, d.CloseCode, CloseWrongCluster)
		}
	}
}

/** A pass minted for one surface and presented from another is a stolen pass being reused. */
func TestOriginMustMatchTheSurfaceThePassWasMintedFor(t *testing.T) {
	key, cfg, now := harness(t)
	cfg.AllowedOrigins = append(cfg.AllowedOrigins, "https://admin.runos.com")
	token := signVM(t, key, func(p *pass.Payload) { p.Org = "https://admin.runos.com" })

	req := sessionRequest(token)
	req.Origin = "https://console.runos.com" // allowed by the gate, but not what the pass names
	if d := Verify(req, cfg, now); d.Allow {
		t.Fatal("a pass minted for another surface was accepted")
	}
}

func TestRefusesAKindThisDoorDoesNotServe(t *testing.T) {
	key, cfg, now := harness(t)
	token := signVM(t, key, func(p *pass.Payload) {
		p.Kind = pass.KindWSFiles
		p.VM = nil
		p.EXP = json.RawMessage("1755800300")
		p.WS = &pass.WSTarget{Service: "runostty-u1", UID: "u1", User: "dev"}
	})
	// /v1/session does not serve ws.files: that is an HTTP kind, not a stream.
	if d := Verify(sessionRequest(token), cfg, now); d.Allow {
		t.Fatal("ws.files was accepted at the websocket door")
	}
}

/** Step 9: a target the control plane should never have emitted. Refused, and logged loudly. */
func TestRefusesATargetConductorShouldNeverEmit(t *testing.T) {
	key, cfg, now := harness(t)
	// pass.Verify refuses these shapes too, which is the point: two independent layers. Signed with
	// a payload built directly so the decoder sees it exactly as conductor would have sent it.
	token := signVM(t, key, func(p *pass.Payload) {
		p.VM = &pass.VMTarget{Namespace: "kube-system", Name: "etcd"}
	})
	d := Verify(sessionRequest(token), cfg, now)
	if d.Allow {
		t.Fatal("a pass naming kube-system was accepted")
	}
	if d.ClientText != refusedText {
		t.Errorf("the client must learn nothing about why: %q", d.ClientText)
	}
}

// --- pre-handshake refusals ---------------------------------------------------------------------

func TestPreHandshakeRefusals(t *testing.T) {
	key, cfg, now := harness(t)
	token := signVM(t, key, nil)

	t.Run("a query string is refused outright", func(t *testing.T) {
		req := sessionRequest(token)
		req.RawQuery = "pass=" + token
		d := Verify(req, cfg, now)
		if d.HTTPStatus != 400 {
			t.Fatalf("status %d, want 400", d.HTTPStatus)
		}
		if d.CloseCode != 0 {
			t.Fatal("this is decidable without the pass, so it must not cost a handshake")
		}
	})

	t.Run("no subprotocol offered", func(t *testing.T) {
		req := sessionRequest(token)
		req.Subprotocols = nil
		if d := Verify(req, cfg, now); d.HTTPStatus != 400 {
			t.Fatalf("status %d, want 400", d.HTTPStatus)
		}
	})

	t.Run("protocol offered but no pass", func(t *testing.T) {
		req := sessionRequest(token)
		req.Subprotocols = []string{SessionProtocol}
		if d := Verify(req, cfg, now); d.HTTPStatus != 400 {
			t.Fatalf("status %d, want 400", d.HTTPStatus)
		}
	})

	t.Run("an enormous pass is refused before anything parses it", func(t *testing.T) {
		req := sessionRequest(strings.Repeat("A", MaxPassBytes+1))
		if d := Verify(req, cfg, now); d.HTTPStatus != 400 {
			t.Fatalf("status %d, want 400", d.HTTPStatus)
		}
	})
}

/** A close reason must never exceed what the protocol allows, whatever it is built from. */
func TestCloseReasonsFitTheProtocol(t *testing.T) {
	d := refuseClose(ClosePassRefused, strings.Repeat("x", 500), "reason")
	if len(d.ClientText) > 123 {
		t.Fatalf("a close reason is capped at 123 bytes, this is %d", len(d.ClientText))
	}
}

package pass

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestGoldenVectors runs every vector in the shared file through the Go verifier.
//
// The SAME file is run by conductor's TypeScript verifier. A vector one side accepts and the other
// refuses is a hole with a green build, which is why the file is a single source rather than two
// parallel fixtures.
func TestGoldenVectors(t *testing.T) {
	f := loadVectors(t)
	keys, now, skew := f.harness(t)

	if len(f.Vectors) < 30 {
		t.Fatalf("the contract calls for at least 30 vectors, the file has %d", len(f.Vectors))
	}

	seenValid := map[string]bool{}
	for _, v := range f.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			p, err := Verify(v.Token, keys, now, skew)
			if v.Expect == "valid" {
				if err != nil {
					t.Fatalf("expected valid, got %v\nwhy this vector exists: %s", err, v.Why)
				}
				seenValid[string(p.Kind)] = true
				// AGREEING ON THE VERDICT IS HALF THE CONTRACT. Two verifiers can both say "valid"
				// and hand their callers different values: a sub decoded with a replacement
				// character, a number one side widens, a field one side drops. Compare the decoded
				// payload field by field against the same expectation conductor compares against.
				if v.Payload != nil {
					assertPayloadMatches(t, p, v.Payload)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected refusal %s, the pass was ACCEPTED\nwhy this vector exists: %s", v.Expect, v.Why)
			}
			if got := CodeOf(err); got != v.Expect {
				t.Fatalf("expected refusal %s, got %s (%v)\nwhy this vector exists: %s", v.Expect, got, err, v.Why)
			}
		})
	}

	// Every kind must have at least one accepted vector. Without this, a change that broke one kind
	// entirely would still show a green run full of refusals behaving exactly as written.
	for _, k := range []Kind{KindVMSSH, KindVMSerial, KindVMVNC, KindWSTerminal, KindWSFiles} {
		if !seenValid[string(k)] {
			t.Errorf("no vector accepts a %s pass", k)
		}
	}
}

// TestEveryRefusalCodeIsExercised keeps the taxonomy honest.
//
// A code no vector produces is a code nobody has checked the wording or the trigger of, and a code
// two vectors disagree about is worse. Both directions are covered: every code appears, and no
// vector expects a code that does not exist.
func TestEveryRefusalCodeIsExercised(t *testing.T) {
	f := loadVectors(t)
	known := map[string]bool{
		ErrMalformed: true, ErrPayload: true, ErrUnknownKey: true,
		ErrBadSignature: true, ErrTarget: true, ErrExpired: true, ErrLifetime: true,
	}
	used := map[string]bool{}
	for _, v := range f.Vectors {
		if v.Expect == "valid" {
			continue
		}
		if !known[v.Expect] {
			t.Errorf("vector %q expects refusal code %q, which is not a code this package defines", v.Name, v.Expect)
		}
		used[v.Expect] = true
	}
	for code := range known {
		if !used[code] {
			t.Errorf("no vector produces refusal code %q", code)
		}
	}
}

// TestSignThenVerifyRoundTrip is the 100-pass cross-check in its Go half: mint many, verify all.
// Conductor runs the same shape against this verifier's vectors from the other side.
func TestSignThenVerifyRoundTrip(t *testing.T) {
	priv, pub, kid := testKey()
	keys := Keys{kid: pub}
	now := func() time.Time { return fixedNow }

	for i := 0; i < 100; i++ {
		p := &Payload{
			// jti must stay 32 LOWERCASE HEX characters: it becomes a Kubernetes object name, so
			// "0123...g" would be refused, and a loop that quietly produced one would look like a
			// verifier bug rather than a test bug.
			V: 1, JTI: "0123456789abcdef0123456789abcd" + hexPair(i),
			IAT: json.RawMessage("1755800000"), EXP: json.RawMessage("1755800060"),
			AID: "rjwrn", CID: "v6b", Sub: "u1", Kind: KindVMSSH, Org: "https://console.runos.com",
			VM: &VMTarget{Namespace: "vmgroup-a1b2c", Name: "vm-abcde"},
		}
		token, err := Sign(p, kid, priv)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		if _, err := Verify(token, keys, now, 30*time.Second); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
}

// A pass minted for one cluster must not open a session on another, even though both are signed by
// keys with the same id shape. The gate holds only ITS cluster's key, so the refusal comes from the
// signature rather than from a field comparison. This test pins that the mechanism is the key, so
// nobody later "simplifies" it into a string compare on cid.
func TestPassFromAnotherClusterDoesNotVerify(t *testing.T) {
	priv, _, kid := testKey()
	otherPriv := ed25519.NewKeyFromSeed([]byte("a-different-clusters-key-0000001"))
	otherPub := otherPriv.Public().(ed25519.PublicKey)

	p := &Payload{
		V: 1, JTI: "0123456789abcdef0123456789abcdef",
		IAT: json.RawMessage("1755800000"), EXP: json.RawMessage("1755800060"),
		AID: "rjwrn", CID: "v6b", Sub: "u1", Kind: KindVMSSH, Org: "https://console.runos.com",
		VM: &VMTarget{Namespace: "vmgroup-a1b2c", Name: "vm-abcde"},
	}
	token, err := Sign(p, kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	// The other cluster's gate holds the same kid pointing at ITS key.
	_, err = Verify(token, Keys{kid: otherPub}, func() time.Time { return fixedNow }, 30*time.Second)
	if CodeOf(err) != ErrBadSignature {
		t.Fatalf("a pass from another cluster must fail the signature check, got %v", err)
	}
}

// Rotation: the gate holds the outgoing and incoming key at once, or every rotation is an outage.
func TestTwoKeysAreHeldDuringRotation(t *testing.T) {
	oldPriv, oldPub, oldKID := testKey()
	newPriv := ed25519.NewKeyFromSeed([]byte("runos-session-gate-test-key-0002"))
	newPub := newPriv.Public().(ed25519.PublicKey)
	const newKID = "b1b2c3d4e5f60718"

	keys := Keys{oldKID: oldPub, newKID: newPub}
	now := func() time.Time { return fixedNow }

	for _, tc := range []struct {
		name string
		priv ed25519.PrivateKey
		kid  string
	}{{"outgoing key", oldPriv, oldKID}, {"incoming key", newPriv, newKID}} {
		p := &Payload{
			V: 1, JTI: "0123456789abcdef0123456789abcdef",
			IAT: json.RawMessage("1755800000"), EXP: json.RawMessage("1755800060"),
			AID: "rjwrn", CID: "v6b", Sub: "u1", Kind: KindVMSSH, Org: "https://console.runos.com",
			VM: &VMTarget{Namespace: "vmgroup-a1b2c", Name: "vm-abcde"},
		}
		token, err := Sign(p, tc.kid, tc.priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(token, keys, now, 30*time.Second); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// An error message must never hand back a large or control-laden field verbatim: refusals are
// logged, and a terminal escape in a log line can lie to whoever reads it.
func TestRefusalDoesNotEchoAttackerBytes(t *testing.T) {
	long := make([]byte, 4096)
	for i := range long {
		long[i] = 'A'
	}
	got := safeEcho(string(long) + "\x1b[2J")
	if len(got) > 80 {
		t.Errorf("safeEcho must bound its output, got %d bytes", len(got))
	}
	for i := 0; i < len(got); i++ {
		if got[i] < 0x20 || got[i] > 0x7e {
			t.Errorf("safeEcho let a control byte through at %d", i)
		}
	}
}

// --- harness -----------------------------------------------------------------------------------

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with: go test ./internal/pass -run TestUpdateVectors -update)", vectorsPath, err)
	}
	var f vectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse %s: %v", vectorsPath, err)
	}
	return f
}

func (f vectorFile) harness(t *testing.T) (Keys, Now, time.Duration) {
	t.Helper()
	pub, err := base64.RawURLEncoding.DecodeString(f.PublicKey)
	if err != nil {
		t.Fatalf("public key in %s is not unpadded base64url: %v", vectorsPath, err)
	}
	at := time.Unix(f.NowUnix, 0).UTC()
	return Keys{f.KID: ed25519.PublicKey(pub)},
		func() time.Time { return at },
		time.Duration(f.SkewSeconds) * time.Second
}

// hexPair turns a loop counter into two lowercase hex characters, so the generated jti stays a
// valid Kubernetes object name for every iteration.
func hexPair(i int) string {
	const hexd = "0123456789abcdef"
	return string([]byte{hexd[(i/16)%16], hexd[i%16]})
}

// assertPayloadMatches compares a decoded pass to the vector's expected payload, field by field.
//
// Deliberately explicit rather than reflective: a reflective compare would need the two languages
// to agree about how a struct maps to a JSON object, which is the very thing under test.
func assertPayloadMatches(t *testing.T, got *Payload, want map[string]any) {
	t.Helper()

	str := func(key string) string {
		v, ok := want[key].(string)
		if !ok {
			t.Fatalf("vector payload field %q is not a string", key)
		}
		return v
	}
	num := func(key string) int64 {
		switch v := want[key].(type) {
		case float64:
			return int64(v)
		case json.Number:
			n, _ := v.Int64()
			return n
		default:
			t.Fatalf("vector payload field %q is not a number", key)
			return 0
		}
	}

	if int64(got.V) != num("v") {
		t.Errorf("v: got %d, vector says %d", got.V, num("v"))
	}
	for _, f := range []struct {
		name string
		got  string
	}{
		{"kid", got.KID}, {"jti", got.JTI}, {"aid", got.AID}, {"cid", got.CID},
		{"sub", got.Sub}, {"kind", string(got.Kind)}, {"org", got.Org},
	} {
		if f.got != str(f.name) {
			t.Errorf("%s: got %q, vector says %q", f.name, f.got, str(f.name))
		}
	}
	if got.IssuedAt().Unix() != num("iat") {
		t.Errorf("iat: got %d, vector says %d", got.IssuedAt().Unix(), num("iat"))
	}
	if got.ExpiresAt().Unix() != num("exp") {
		t.Errorf("exp: got %d, vector says %d", got.ExpiresAt().Unix(), num("exp"))
	}

	if wantVM, ok := want["vm"].(map[string]any); ok {
		if got.VM == nil {
			t.Fatalf("vector expects a vm target, the pass decoded without one")
		}
		if got.VM.Namespace != wantVM["ns"] || got.VM.Name != wantVM["name"] {
			t.Errorf("vm: got %+v, vector says %+v", *got.VM, wantVM)
		}
	} else if got.VM != nil {
		t.Errorf("the pass decoded a vm target the vector does not expect")
	}

	if wantWS, ok := want["ws"].(map[string]any); ok {
		if got.WS == nil {
			t.Fatalf("vector expects a ws target, the pass decoded without one")
		}
		for _, f := range []struct {
			name string
			got  string
		}{
			{"svc", got.WS.Service}, {"uid", got.WS.UID}, {"user", got.WS.User},
			{"dir", got.WS.Dir}, {"cmd", got.WS.Cmd},
		} {
			if f.got != wantWS[f.name] {
				t.Errorf("ws.%s: got %q, vector says %v", f.name, f.got, wantWS[f.name])
			}
		}
	} else if got.WS != nil {
		t.Errorf("the pass decoded a ws target the vector does not expect")
	}
}

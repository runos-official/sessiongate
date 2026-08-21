package pass

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The golden vectors are the CONTRACT between the two implementations.
//
// Both the Go verifier here and conductor's TypeScript verifier read this one file and must agree
// on every verdict. That is the whole point: two implementations that each pass their own tests
// prove nothing about whether they agree with each other, and a pass that one accepts and the other
// refuses is a security hole with a green build.
//
// Tokens in the file are CONCRETE STRINGS, not recipes. A recipe would have to be implemented twice
// and could be implemented differently twice, which is the bug the file exists to prevent. They are
// regenerated with:
//
//	go test ./internal/pass -run TestUpdateVectors -update
//
// The key is fixed and its private half is IN the file on purpose: it is a test key, it signs
// nothing real, and both languages need it to verify. Never let a cluster key near this file.

var update = flag.Bool("update", false, "regenerate testdata/passes.json")

const vectorsPath = "testdata/passes.json"

// A fixed seed, so regenerating the file with no case changes produces no diff.
var testSeed = []byte("runos-session-gate-test-key-0001")

type vectorFile struct {
	Comment     string   `json:"comment"`
	KID         string   `json:"kid"`
	PublicKey   string   `json:"publicKeyB64url"`
	PrivateSeed string   `json:"privateKeySeedB64url"`
	NowUnix     int64    `json:"nowUnix"`
	SkewSeconds int      `json:"skewSeconds"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	Name   string `json:"name"`
	Why    string `json:"why"`
	Token  string `json:"token"`
	Expect string `json:"expect"`
}

func testKey() (ed25519.PrivateKey, ed25519.PublicKey, string) {
	priv := ed25519.NewKeyFromSeed(testSeed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, "a1b2c3d4e5f60718"
}

// fixedNow is the clock every time-dependent vector is written against.
var fixedNow = time.Unix(1755800030, 0).UTC()

func basePayload(kind Kind) map[string]any {
	p := map[string]any{
		"v":    1,
		"kid":  "a1b2c3d4e5f60718",
		"jti":  "0123456789abcdef0123456789abcdef",
		"iat":  1755800000,
		"exp":  1755800060,
		"aid":  "rjwrn",
		"cid":  "v6b",
		"sub":  "GK2xQ7mUeZbN4hVt0pLrYcSd3fA1",
		"kind": string(kind),
		"org":  "https://console.runos.com",
	}
	if kind.IsVM() {
		p["vm"] = map[string]any{"ns": "vmgroup-a1b2c", "name": "vm-abcde"}
	} else {
		p["ws"] = map[string]any{
			"svc": "runostty-gk2xq7muezbn4hvt0plrycsd3fa1", "uid": "GK2xQ7mUeZbN4hVt0pLrYcSd3fA1",
			"user": "dev", "dir": "/home/dev/proj", "cmd": "",
		}
	}
	return p
}

func TestUpdateVectors(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate testdata/passes.json")
	}
	priv, pub, kid := testKey()

	sign := func(p map[string]any) string {
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return SignRaw(b, priv)
	}
	signRawJSON := func(s string) string { return SignRaw([]byte(s), priv) }

	var vs []vector
	add := func(name, why, token, expect string) {
		vs = append(vs, vector{Name: name, Why: why, Token: token, Expect: expect})
	}

	// --- valid, one per kind -------------------------------------------------------------------
	for _, k := range []Kind{KindVMSSH, KindVMSerial, KindVMVNC, KindWSTerminal, KindWSFiles} {
		p := basePayload(k)
		if k == KindWSFiles {
			// ws.files legitimately carries the longer window.
			p["exp"] = 1755800300
		}
		add("valid-"+string(k), "a well-formed pass of every kind must verify", sign(p), "valid")
	}

	// --- structure -----------------------------------------------------------------------------
	valid := sign(basePayload(KindVMSSH))
	add("wrong-prefix", "the version prefix is inside the signature, so a v2 pass cannot be read as v1",
		"runos_pass_v2"+valid[len(Prefix):], ErrMalformed)
	add("two-segments", "a pass has exactly three segments", "runos_pass_v1."+splitSeg(valid, 1), ErrMalformed)
	add("four-segments", "a fourth segment must be refused, not ignored", valid+".extra", ErrMalformed)
	add("empty-payload-segment", "an empty segment is not a payload", "runos_pass_v1..AAAA", ErrMalformed)
	add("padded-base64", "a subprotocol value must be an HTTP token and '=' is not one",
		"runos_pass_v1."+base64.URLEncoding.EncodeToString([]byte(`{"v":1}`))+"."+splitSeg(valid, 2), ErrMalformed)
	add("standard-alphabet-base64", "'+' and '/' are not token characters either",
		"runos_pass_v1.eyJ2Ijox+w."+splitSeg(valid, 2), ErrMalformed)
	add("short-signature", "a truncated signature is a transport fault, named as one",
		"runos_pass_v1."+splitSeg(valid, 1)+".AAAA", ErrMalformed)
	add("bad-signature", "a flipped signature byte must not verify",
		"runos_pass_v1."+splitSeg(valid, 1)+"."+flipLast(splitSeg(valid, 2)), ErrBadSignature)
	add("payload-tampered", "changing the payload after signing must not verify",
		func() string {
			p := basePayload(KindVMSSH)
			p["vm"] = map[string]any{"ns": "vmgroup-zzzzz", "name": "vm-other"}
			b, _ := json.Marshal(p)
			return Prefix + "." + base64.RawURLEncoding.EncodeToString(b) + "." + splitSeg(valid, 2)
		}(), ErrBadSignature)

	// --- key identification --------------------------------------------------------------------
	add("unknown-kid", "a kid the gate does not hold is refused without naming the keys it does hold",
		sign(withKey(basePayload(KindVMSSH), "kid", "ffffffffffffffff")), ErrUnknownKey)
	add("kid-wrong-length", "kid is exactly 16 lowercase hex characters",
		sign(withKey(basePayload(KindVMSSH), "kid", "a1b2c3")), ErrPayload)
	add("kid-uppercase", "an uppercase kid would be a second name for one key",
		sign(withKey(basePayload(KindVMSSH), "kid", "A1B2C3D4E5F60718")), ErrPayload)

	// --- payload shape -------------------------------------------------------------------------
	add("payload-not-object", "a JSON array is valid JSON and not a pass body", signRawJSON(`[1,2,3]`), ErrPayload)
	add("payload-null", "bare null is valid JSON and not a pass body", signRawJSON(`null`), ErrPayload)
	add("payload-trailing-content", "bytes after the object were signed and never read",
		signRawJSON(`{"v":1}{"v":2}`), ErrPayload)
	add("unknown-field", "an unknown field is refused, which is what stops a smuggled port",
		signRawJSON(`{"v":1,"kid":"a1b2c3d4e5f60718","jti":"0123456789abcdef0123456789abcdef","iat":1755800000,"exp":1755800060,"aid":"rjwrn","cid":"v6b","sub":"u1","kind":"vm.ssh","org":"https://console.runos.com","vm":{"ns":"vmgroup-a1b2c","name":"vm-abcde"},"port":2222}`), ErrPayload)
	add("unknown-field-in-vm", "and inside the target block too",
		signRawJSON(`{"v":1,"kid":"a1b2c3d4e5f60718","jti":"0123456789abcdef0123456789abcdef","iat":1755800000,"exp":1755800060,"aid":"rjwrn","cid":"v6b","sub":"u1","kind":"vm.ssh","org":"https://console.runos.com","vm":{"ns":"vmgroup-a1b2c","name":"vm-abcde","port":2222}}`), ErrPayload)
	add("duplicate-key", "two parsers may keep different values for a duplicated key; refuse the shape",
		signRawJSON(`{"v":1,"kid":"a1b2c3d4e5f60718","jti":"0123456789abcdef0123456789abcdef","iat":1755800000,"exp":1755800060,"aid":"rjwrn","cid":"v6b","sub":"u1","kind":"ws.files","kind":"vm.ssh","org":"https://console.runos.com","vm":{"ns":"vmgroup-a1b2c","name":"vm-abcde"}}`), ErrPayload)
	add("missing-field", "every field is required",
		signRawJSON(`{"v":1,"kid":"a1b2c3d4e5f60718","jti":"0123456789abcdef0123456789abcdef","iat":1755800000,"exp":1755800060,"aid":"rjwrn","cid":"v6b","kind":"vm.ssh","org":"https://console.runos.com","vm":{"ns":"vmgroup-a1b2c","name":"vm-abcde"}}`), ErrPayload)
	add("wrong-version", "a version 2 body under a v1 prefix", sign(withKey(basePayload(KindVMSSH), "v", 2)), ErrPayload)
	add("unknown-kind", "a kind the gate does not implement", sign(withKey(basePayload(KindVMSSH), "kind", "vm.rdp")), ErrPayload)
	add("sub-non-ascii", "a homoglyph subject is a second identity for one person",
		sign(withKey(basePayload(KindVMSSH), "sub", "GK2xQ7mUeZbN4hVt0pLrYcSd3fΑ1")), ErrPayload)

	// --- numbers -------------------------------------------------------------------------------
	add("exp-fractional", "1755800060.0 is one number in JavaScript and another in Go",
		signRawJSON(numBody(`1755800000`, `1755800060.0`)), ErrPayload)
	add("exp-exponent", "1.75580006e9 is the same trap in another spelling",
		signRawJSON(numBody(`1755800000`, `1.75580006e9`)), ErrPayload)
	add("exp-string", "a quoted number is not a number", signRawJSON(numBody(`1755800000`, `"1755800060"`)), ErrPayload)
	add("iat-negative", "a negative issue time", signRawJSON(numBody(`-1`, `1755800060`)), ErrPayload)
	add("exp-huge", "an exp beyond int64 seconds", signRawJSON(numBody(`1755800000`, `99999999999999999999`)), ErrPayload)
	add("iat-string", "and the same trap on iat, which Go accepted into a json.Number until this vector",
		signRawJSON(numBody(`"1755800000"`, `1755800060`)), ErrPayload)
	add("exp-leading-zero", "a number with two readings has no place in a credential",
		signRawJSON(numBody(`1755800000`, `01755800060`)), ErrPayload)
	add("exp-plus-prefix", "a leading plus is legal in some parsers and not in JSON",
		signRawJSON(numBody(`1755800000`, `+1755800060`)), ErrPayload)

	// --- lifetime and freshness ------------------------------------------------------------------
	add("expired", "exp in the past, beyond the skew allowance",
		sign(withKey(withKey(basePayload(KindVMSSH), "iat", 1755000000), "exp", 1755000060)), ErrExpired)
	add("not-yet-valid", "iat in the future, beyond the skew allowance",
		sign(withKey(withKey(basePayload(KindVMSSH), "iat", 1755900000), "exp", 1755900060)), ErrExpired)
	add("exp-equals-iat", "a pass that expires when it was issued",
		sign(withKey(basePayload(KindVMSSH), "exp", 1755800000)), ErrLifetime)
	add("exp-before-iat", "an inverted window", sign(withKey(basePayload(KindVMSSH), "exp", 1755799000)), ErrLifetime)
	add("lifetime-over-cap", "a session pass may live 60 seconds however long it claims",
		sign(withKey(basePayload(KindVMSSH), "exp", 1755886400)), ErrLifetime)
	add("ws-files-lifetime-over-cap", "and ws.files 300, not more",
		sign(withKey(basePayload(KindWSFiles), "exp", 1755800600)), ErrLifetime)
	add("clock-skew-tolerated", "a pass a few seconds stale still opens, or a fast cluster clock breaks every session",
		sign(withKey(withKey(basePayload(KindVMSSH), "iat", 1755799965), "exp", 1755800025)), "valid")

	// --- target confusion ------------------------------------------------------------------------
	add("both-targets", "the interesting version rides a vm block on a ws kind",
		signRawJSON(`{"v":1,"kid":"a1b2c3d4e5f60718","jti":"0123456789abcdef0123456789abcdef","iat":1755800000,"exp":1755800060,"aid":"rjwrn","cid":"v6b","sub":"u1","kind":"ws.files","org":"https://console.runos.com","vm":{"ns":"vmgroup-a1b2c","name":"vm-abcde"},"ws":{"svc":"runostty-u1","uid":"u1","user":"dev","dir":"","cmd":""}}`), ErrTarget)
	add("no-target", "a pass with nothing to open",
		signRawJSON(`{"v":1,"kid":"a1b2c3d4e5f60718","jti":"0123456789abcdef0123456789abcdef","iat":1755800000,"exp":1755800060,"aid":"rjwrn","cid":"v6b","sub":"u1","kind":"vm.ssh","org":"https://console.runos.com"}`), ErrTarget)
	add("kind-target-mismatch", "a vm kind carrying a ws block",
		signRawJSON(`{"v":1,"kid":"a1b2c3d4e5f60718","jti":"0123456789abcdef0123456789abcdef","iat":1755800000,"exp":1755800060,"aid":"rjwrn","cid":"v6b","sub":"u1","kind":"vm.ssh","org":"https://console.runos.com","ws":{"svc":"runostty-u1","uid":"u1","user":"dev","dir":"","cmd":""}}`), ErrTarget)
	add("ns-kube-system", "a signed pass must not be able to name a cluster namespace",
		sign(withVM(basePayload(KindVMSSH), "kube-system", "vm-abcde")), ErrTarget)
	add("ns-traversal", "dot-dot in a namespace",
		sign(withVM(basePayload(KindVMSSH), "vmgroup-../kube-system", "vm-abcde")), ErrTarget)
	add("ns-gate-namespace", "the gate's own namespace is not a VM group",
		sign(withVM(basePayload(KindVMSSH), "runos", "vm-abcde")), ErrTarget)
	add("name-subresource-injection", "a name that continues the subresource path",
		sign(withVM(basePayload(KindVMSSH), "vmgroup-a1b2c", "vm-abcde/portforward/9999/tcp")), ErrTarget)
	add("name-encoded-slash", "an encoded slash is still a slash to something downstream",
		sign(withVM(basePayload(KindVMSSH), "vmgroup-a1b2c", "vm-abcde%2fportforward")), ErrTarget)
	add("name-query-injection", "a query string appended to the name",
		sign(withVM(basePayload(KindVMSSH), "vmgroup-a1b2c", "vm-abcde?port=9999")), ErrTarget)
	add("name-absolute-url", "a name that is a whole URL",
		sign(withVM(basePayload(KindVMSSH), "vmgroup-a1b2c", "https://evil.example.com/x")), ErrTarget)
	add("name-uppercase", "Kubernetes object names are lowercase",
		sign(withVM(basePayload(KindVMSSH), "vmgroup-a1b2c", "VM-ABCDE")), ErrTarget)
	add("name-empty", "an empty machine name", sign(withVM(basePayload(KindVMSSH), "vmgroup-a1b2c", "")), ErrTarget)
	add("ws-svc-injection", "the same path injection through a workspace service name",
		sign(withWS(basePayload(KindWSTerminal), "runostty-u1/../../x")), ErrTarget)

	// --- jti -------------------------------------------------------------------------------------
	add("jti-wrong-length", "jti becomes a Kubernetes object name and its length is fixed",
		sign(withKey(basePayload(KindVMSSH), "jti", "0123456789abcdef")), ErrPayload)
	add("jti-uppercase", "an uppercase jti is not a valid object name, so single-use would silently not apply",
		sign(withKey(basePayload(KindVMSSH), "jti", "0123456789ABCDEF0123456789ABCDEF")), ErrPayload)
	add("jti-not-hex", "and it must actually be hex",
		sign(withKey(basePayload(KindVMSSH), "jti", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")), ErrPayload)

	f := vectorFile{
		Comment: "Golden vectors for the RunOS session pass. Read by BOTH the Go verifier in " +
			"sessiongate and the TypeScript verifier in conductor; both must agree on every verdict. " +
			"Regenerate with: go test ./internal/pass -run TestUpdateVectors -update. The private key " +
			"seed is a TEST key and signs nothing real.",
		KID:         kid,
		PublicKey:   base64.RawURLEncoding.EncodeToString(pub),
		PrivateSeed: base64.RawURLEncoding.EncodeToString(testSeed),
		NowUnix:     fixedNow.Unix(),
		SkewSeconds: 30,
		Vectors:     vs,
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d vectors to %s", len(vs), vectorsPath)
}

// --- helpers used only to build vectors --------------------------------------------------------

func withKey(p map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for key, val := range p {
		out[key] = val
	}
	out[k] = v
	return out
}

func withVM(p map[string]any, ns, name string) map[string]any {
	out := withKey(p, "vm", map[string]any{"ns": ns, "name": name})
	return out
}

func withWS(p map[string]any, svc string) map[string]any {
	return withKey(p, "ws", map[string]any{
		"svc": svc, "uid": "u1", "user": "dev", "dir": "", "cmd": "",
	})
}

func numBody(iat, exp string) string {
	return `{"v":1,"kid":"a1b2c3d4e5f60718","jti":"0123456789abcdef0123456789abcdef","iat":` + iat +
		`,"exp":` + exp + `,"aid":"rjwrn","cid":"v6b","sub":"u1","kind":"vm.ssh",` +
		`"org":"https://console.runos.com","vm":{"ns":"vmgroup-a1b2c","name":"vm-abcde"}}`
}

func splitSeg(token string, i int) string {
	n := 0
	start := 0
	for j := 0; j < len(token); j++ {
		if token[j] == '.' {
			if n == i {
				return token[start:j]
			}
			n++
			start = j + 1
		}
	}
	if n == i {
		return token[start:]
	}
	return ""
}

func flipLast(seg string) string {
	if seg == "" {
		return seg
	}
	b := []byte(seg)
	if b[len(b)-1] == 'A' {
		b[len(b)-1] = 'B'
	} else {
		b[len(b)-1] = 'A'
	}
	return string(b)
}

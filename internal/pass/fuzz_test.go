package pass

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"crypto/ed25519"
)

// FuzzVerifyNeverPanics throws arbitrary and mutated bytes at Verify and asserts the ONE property a
// security boundary must hold under any input: it returns, it never panics, and it never returns a
// payload together with an error. A verifier that panics is a denial of service reachable by an
// unauthenticated client, since the token arrives before any check.
//
// Seeded from the golden vectors so the corpus starts near the valid/invalid boundary, where a
// parser is most likely to mishandle a truncation or a flipped byte. Run:
//
//	go test ./internal/pass -run x -fuzz FuzzVerifyNeverPanics -fuzztime 30s
func FuzzVerifyNeverPanics(f *testing.F) {
	b, err := os.ReadFile("testdata/passes.json")
	if err != nil {
		f.Fatalf("read vectors: %v", err)
	}
	var file struct {
		KID             string `json:"kid"`
		PublicKeyB64url string `json:"publicKeyB64url"`
		NowUnix         int64  `json:"nowUnix"`
		SkewSeconds     int    `json:"skewSeconds"`
		Vectors         []struct {
			Token string `json:"token"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		f.Fatalf("parse vectors: %v", err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(file.PublicKeyB64url)
	if err != nil {
		f.Fatalf("public key: %v", err)
	}
	keys := Keys{file.KID: ed25519.PublicKey(pub)}
	now := func() time.Time { return time.Unix(file.NowUnix, 0).UTC() }
	skew := time.Duration(file.SkewSeconds) * time.Second

	for _, v := range file.Vectors {
		f.Add(v.Token)
	}
	// A few shapes the vectors do not include: an empty token, one huge token, and one that is all
	// the separators, so the seed corpus exercises the length and split paths too.
	f.Add("")
	f.Add("runos_pass_v1..")
	f.Add("runos_pass_v1." + string(make([]byte, 100000)))

	f.Fuzz(func(t *testing.T, token string) {
		p, err := Verify(token, keys, now, skew)
		if err != nil && p != nil {
			t.Fatalf("Verify returned BOTH a payload and an error for %q: a caller that checks err==nil last would act on a rejected pass", token)
		}
		if err == nil && p == nil {
			t.Fatalf("Verify accepted %q but returned no payload", token)
		}
	})
}

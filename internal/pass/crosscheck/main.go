// Command crosscheck asks the GATE's verifier whether it accepts passes minted by CONDUCTOR.
//
// The golden vectors hold the two implementations to the same verdicts on a frozen set of inputs.
// This is the other direction and catches a different failure: conductor emitting something no gate
// will take, from code paths the vectors do not exercise (its own JSON serialiser, its own field
// order, its own key handling).
//
// Reads a JSON array of {"kind","token"} on stdin, as
// conductor/scripts/mint-for-gate-crosscheck.ts prints it. Exits non-zero on the first refusal.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"crypto/ed25519"

	"github.com/runos-official/sessiongate/internal/pass"
)

type minted struct {
	Kind  string `json:"kind"`
	Token string `json:"token"`
}

func main() {
	vectorFile, err := os.ReadFile("internal/pass/testdata/passes.json")
	if err != nil {
		fail("read vectors: %v", err)
	}
	var vf struct {
		KID       string `json:"kid"`
		PublicKey string `json:"publicKeyB64url"`
		NowUnix   int64  `json:"nowUnix"`
	}
	if err := json.Unmarshal(vectorFile, &vf); err != nil {
		fail("parse vectors: %v", err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(vf.PublicKey)
	if err != nil {
		fail("public key: %v", err)
	}

	var passes []minted
	if err := json.NewDecoder(os.Stdin).Decode(&passes); err != nil {
		fail("read minted passes on stdin: %v", err)
	}
	if len(passes) == 0 {
		fail("no passes on stdin; a silent pass on an empty set is how this check stops checking")
	}

	keys := pass.Keys{vf.KID: ed25519.PublicKey(pub)}
	now := func() time.Time { return time.Unix(vf.NowUnix, 0).UTC() }

	seen := map[string]int{}
	for i, m := range passes {
		p, err := pass.Verify(m.Token, keys, now, 30*time.Second)
		if err != nil {
			fail("pass %d (%s) minted by conductor was REFUSED by the gate: %v", i, m.Kind, err)
		}
		if string(p.Kind) != m.Kind {
			fail("pass %d: conductor says %s, the gate decoded %s", i, m.Kind, p.Kind)
		}
		seen[m.Kind]++
	}

	for _, k := range []string{"vm.ssh", "vm.serial", "vm.vnc", "ws.terminal", "ws.files"} {
		if seen[k] == 0 {
			fail("no %s pass in the set: a kind nobody minted is a kind nobody checked", k)
		}
	}
	fmt.Printf("gate accepted all %d conductor-minted passes: %v\n", len(passes), seen)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

package workspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/runos-official/sessiongate/internal/pass"
)

func wsPass(svc, user, dir, cmd string) *pass.Payload {
	return &pass.Payload{
		V: 1, KID: "a1b2c3d4e5f60718", JTI: "0123456789abcdef0123456789abcdef",
		IAT: json.RawMessage("1755800000"), EXP: json.RawMessage("1755800060"),
		AID: "rjwrn", CID: "v6b", Sub: "u1", Kind: pass.KindWSTerminal, Org: "o",
		WS: &pass.WSTarget{Service: svc, UID: "u1", User: user, Dir: dir, Cmd: cmd},
	}
}

func TestResolveAcceptsAWorkspace(t *testing.T) {
	target, err := Resolve(wsPass("runostty-gk2xq7m", "dev", "/home/dev/proj", "k9s"))
	if err != nil {
		t.Fatal(err)
	}
	if got := target.URL("ws", "/"); got != "ws://runostty-gk2xq7m.runos.svc:7681/" {
		t.Fatalf("got %s", got)
	}
}

/**
 * The host is BUILT, never taken from the pass. A pass that could name a host could name the gate's
 * own address or something outside the cluster, which is server-side request forgery with a
 * signature on it. This asserts the built host contains only what the gate decided plus the service
 * name.
 */
func TestTheHostIsBuiltFromAFixedNamespaceAndPort(t *testing.T) {
	target, err := Resolve(wsPass("runostty-abc", "dev", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	url := target.URL("http", "/files")
	for _, want := range []string{"runostty-abc", ".runos.svc", ":7681", "/files"} {
		if !strings.Contains(url, want) {
			t.Errorf("built %q, missing %q", url, want)
		}
	}
	if strings.Count(url, "://") != 1 {
		t.Errorf("built %q, which looks like it carries a second URL", url)
	}
}

func TestResolveRefusesUnaddressableWorkspaces(t *testing.T) {
	for _, tc := range []struct{ name, svc, user, dir, cmd string }{
		{"a service that is not a workspace", "kubernetes", "dev", "", ""},
		{"traversal in the service", "runostty-../kube-system", "dev", "", ""},
		{"a slash in the service", "runostty-a/b", "dev", "", ""},
		{"uppercase service", "RUNOSTTY-ABC", "dev", "", ""},
		{"empty service", "", "dev", "", ""},
		{"a login that does not exist", "runostty-abc", "root", "", ""},
		{"an empty login", "runostty-abc", "", "", ""},
		{"a relative working directory", "runostty-abc", "dev", "home/dev", ""},
		{"traversal in the directory", "runostty-abc", "dev", "/home/dev/../../etc", ""},
		{"an enormous directory", "runostty-abc", "dev", "/" + strings.Repeat("a", 600), ""},
		{"an enormous command", "runostty-abc", "dev", "", strings.Repeat("a", 600)},
	} {
		if _, err := Resolve(wsPass(tc.svc, tc.user, tc.dir, tc.cmd)); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}

func TestResolveRefusesAVmPass(t *testing.T) {
	p := wsPass("runostty-abc", "dev", "", "")
	p.WS = nil
	if _, err := Resolve(p); err == nil {
		t.Error("a pass with no ws target was accepted")
	}
}

/** Fixed, like the SSH pin: a configurable port is indistinguishable from an attacker-chosen one. */
func TestThePortIsFixed(t *testing.T) {
	if Port != 7681 {
		t.Fatalf("the workspace terminal port is 7681, this says %d", Port)
	}
}

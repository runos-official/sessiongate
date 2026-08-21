package kubevirt

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/runos-official/sessiongate/internal/pass"
)

const apiHost = "10.96.0.1:443"

func vmPass(kind pass.Kind, ns, name string) *pass.Payload {
	return &pass.Payload{
		V: 1, KID: "a1b2c3d4e5f60718", JTI: "0123456789abcdef0123456789abcdef",
		IAT: json.RawMessage("1755800000"), EXP: json.RawMessage("1755800060"),
		AID: "rjwrn", CID: "v6b", Sub: "u1", Kind: kind, Org: "https://console.runos.com",
		VM: &pass.VMTarget{Namespace: ns, Name: name},
	}
}

/**
 * The exact URL, by string equality, for every VM kind.
 *
 * Written as literals rather than built from the same helpers the code uses, because a test that
 * constructs its expectation the way the code does agrees with the code by construction and can
 * never catch a change to it.
 */
func TestSubresourceURLsAreExact(t *testing.T) {
	for _, tc := range []struct {
		kind pass.Kind
		want string
	}{
		{pass.KindVMSerial, "wss://10.96.0.1:443/apis/subresources.kubevirt.io/v1/namespaces/vmgroup-a1b2c/virtualmachineinstances/vm-abcde/console"},
		{pass.KindVMVNC, "wss://10.96.0.1:443/apis/subresources.kubevirt.io/v1/namespaces/vmgroup-a1b2c/virtualmachineinstances/vm-abcde/vnc"},
		{pass.KindVMSSH, "wss://10.96.0.1:443/apis/subresources.kubevirt.io/v1/namespaces/vmgroup-a1b2c/virtualmachineinstances/vm-abcde/portforward/22/tcp"},
	} {
		target, err := Resolve(vmPass(tc.kind, "vmgroup-a1b2c", "vm-abcde"))
		if err != nil {
			t.Fatalf("%s: %v", tc.kind, err)
		}
		if got := target.URL(apiHost); got != tc.want {
			t.Errorf("%s:\n got  %s\n want %s", tc.kind, got, tc.want)
		}
	}
}

/**
 * FUZZ: whatever arrives, an SSH session ends at exactly /portforward/22/tcp or does not dial.
 *
 * Deliberately does NOT reference SSHPort. A test that names the constant proves the constant equals
 * itself and passes happily after someone changes it to 2222. This one hard-codes the string a
 * customer's firewall was told to expect.
 */
func FuzzSSHTargetAlwaysEndsAt22(f *testing.F) {
	f.Add("vmgroup-a1b2c", "vm-abcde")
	f.Add("vmgroup-zzzzz", "a")
	f.Add("vmgroup-a1b2c", "vm-abcde/portforward/3306/tcp")
	f.Add("vmgroup-a1b2c", "../../../api/v1/nodes")
	f.Add("kube-system", "etcd")
	f.Add("vmgroup-a1b2c", "vm%2fabcde")

	f.Fuzz(func(t *testing.T, ns, name string) {
		target, err := Resolve(vmPass(pass.KindVMSSH, ns, name))
		if err != nil {
			return // refused, which is the other acceptable outcome
		}
		got := target.URL(apiHost)
		if !strings.HasSuffix(got, "/portforward/22/tcp") {
			t.Fatalf("an accepted vm.ssh target built %q, which does not end at port 22", got)
		}
		// One occurrence only: a name that smuggled a second portforward segment past Resolve would
		// still end correctly while reaching something else on the way.
		if strings.Count(got, "portforward") != 1 {
			t.Fatalf("built %q, which names portforward more than once", got)
		}
		if strings.Contains(got, "..") {
			t.Fatalf("built %q, which contains a traversal", got)
		}
	})
}

func TestResolveRefusesUnaddressableTargets(t *testing.T) {
	for _, tc := range []struct{ name, ns, vm string }{
		{"a cluster namespace", "kube-system", "etcd"},
		{"the gate's own namespace", "runos", "runos-session-gate"},
		{"default", "default", "x"},
		{"traversal in the namespace", "vmgroup-../kube-system", "vm-abcde"},
		{"traversal in the name", "vmgroup-a1b2c", "../../../api/v1/nodes"},
		{"subresource continuation", "vmgroup-a1b2c", "vm-abcde/portforward/3306/tcp"},
		{"encoded slash", "vmgroup-a1b2c", "vm-abcde%2fportforward"},
		{"query string", "vmgroup-a1b2c", "vm-abcde?x=1"},
		{"uppercase name", "vmgroup-a1b2c", "VM-ABCDE"},
		{"empty name", "vmgroup-a1b2c", ""},
		{"namespace too long", "vmgroup-" + strings.Repeat("a", 33), "vm-abcde"},
		{"a whole URL", "vmgroup-a1b2c", "https://evil.example.com/x"},
	} {
		if _, err := Resolve(vmPass(pass.KindVMSSH, tc.ns, tc.vm)); err == nil {
			t.Errorf("%s: ns=%q name=%q was accepted", tc.name, tc.ns, tc.vm)
		}
	}
}

func TestSubresourcePathRefusesWorkspaceKinds(t *testing.T) {
	for _, k := range []pass.Kind{pass.KindWSTerminal, pass.KindWSFiles, pass.Kind("vm.rdp"), pass.Kind("")} {
		if _, err := SubresourcePath(k); err == nil {
			t.Errorf("%q was accepted as a VM subresource", k)
		}
	}
}

/**
 * The last line of defence. These assertions are about the PANIC firing, because an error return in
 * its place is exactly what a later edit would log and continue past.
 */
func TestAssertSSHPortPinned(t *testing.T) {
	mustPanic := func(name string, kind pass.Kind, url string) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: no panic for %q", name, url)
			}
		}()
		AssertSSHPortPinned(kind, url)
	}

	base := "wss://h/apis/subresources.kubevirt.io/v1/namespaces/vmgroup-a/virtualmachineinstances/vm-b"
	mustPanic("another port", pass.KindVMSSH, base+"/portforward/3306/tcp")
	mustPanic("udp", pass.KindVMSSH, base+"/portforward/22/udp")
	mustPanic("trailing segment", pass.KindVMSSH, base+"/portforward/22/tcp/extra")
	mustPanic("port-forward on a serial kind", pass.KindVMSerial, base+"/portforward/22/tcp")
	mustPanic("port-forward on a workspace kind", pass.KindWSTerminal, base+"/portforward/22/tcp")

	// The two shapes that must NOT panic: a correct SSH dial, and a console dial that never mentions
	// port-forwarding at all.
	AssertSSHPortPinned(pass.KindVMSSH, base+"/portforward/22/tcp")
	AssertSSHPortPinned(pass.KindVMSerial, base+"/console")
	AssertSSHPortPinned(pass.KindVMVNC, base+"/vnc")
}

/**
 * The pin is a promise to a customer's firewall, so this asserts the LITERAL rather than the
 * constant. If someone changes SSHPort, this test is the one that says the promise changed.
 */
func TestTheOnlyPortIs22(t *testing.T) {
	sub, err := SubresourcePath(pass.KindVMSSH)
	if err != nil {
		t.Fatal(err)
	}
	if sub != "portforward/22/tcp" {
		t.Fatalf("the SSH subresource is %q; a customer's firewall was told 22", sub)
	}
}

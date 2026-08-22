package kubevirt

import (
	"strings"
	"testing"

	"github.com/runos-official/sessiongate/internal/pass"
)

/*
A VM NAMED AFTER THE SUBRESOURCE MUST NOT TRIP THE PORT PIN.

The guard used to ask whether the URL contained the word "portforward" anywhere. The VM name is
interpolated into that URL, so a customer who called a machine "portforward-test" made every serial
and VNC session on it panic: the word was present, the kind was not vm.ssh, and the guard fired on a
session that was never a port-forward. The panic then leaked its hijacked socket, so one badly-named
VM was a denial of service against the whole cluster, reachable by its owner at no cost.
*/
func TestAVMNamedPortforwardDoesNotTripThePin(t *testing.T) {
	for _, name := range []string{
		"portforward",
		"portforward-test",
		"my-portforward-box",
		"portforward-22-tcp",
	} {
		for _, k := range []pass.Kind{pass.KindVMSerial, pass.KindVMVNC} {
			target, err := Resolve(&pass.Payload{
				Kind: k,
				VM:   &pass.VMTarget{Namespace: "vmgroup-abcde", Name: name},
			})
			if err != nil {
				t.Fatalf("resolve %s/%s: %v", k, name, err)
			}
			url := target.URL("kubernetes.default.svc")
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						t.Errorf("a VM named %q panicked a %s session: %v", name, k, rec)
					}
				}()
				AssertSSHPortPinned(k, url)
			}()
		}
	}
}

// The pin itself must still be absolute for the kind it guards.
func TestThePinStillRefusesEveryPortButTwentyTwo(t *testing.T) {
	for _, url := range []string{
		"wss://h/apis/subresources.kubevirt.io/v1/namespaces/n/virtualmachineinstances/v/portforward/2222/tcp",
		"wss://h/apis/subresources.kubevirt.io/v1/namespaces/n/virtualmachineinstances/v/portforward/3306/tcp",
		"wss://h/apis/subresources.kubevirt.io/v1/namespaces/n/virtualmachineinstances/v/console",
	} {
		func() {
			defer func() {
				if rec := recover(); rec == nil {
					t.Errorf("vm.ssh was allowed to dial %q", url)
				}
			}()
			AssertSSHPortPinned(pass.KindVMSSH, url)
		}()
	}
}

// And a non-ssh kind must never reach a port-forward, however it got there.
func TestOnlySSHMayPortForward(t *testing.T) {
	url := "wss://h/apis/subresources.kubevirt.io/v1/namespaces/n/virtualmachineinstances/v/portforward/22/tcp"
	for _, k := range []pass.Kind{pass.KindVMSerial, pass.KindVMVNC, pass.KindWSTerminal} {
		func() {
			defer func() {
				if rec := recover(); rec == nil {
					t.Errorf("kind %s was allowed to open a port-forward", k)
				}
			}()
			AssertSSHPortPinned(k, url)
		}()
	}
	// The happy path stays happy.
	defer func() {
		if rec := recover(); rec != nil {
			t.Errorf("vm.ssh to port 22 panicked: %v", rec)
		}
	}()
	AssertSSHPortPinned(pass.KindVMSSH, url)
	if !strings.HasSuffix(url, "/portforward/22/tcp") {
		t.Fatal("test URL is wrong")
	}
}

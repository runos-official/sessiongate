// Package kubevirt builds the one URL a VM session is allowed to reach.
//
// THE PORT 22 PIN IS THE WHOLE POINT OF THIS FILE.
//
// MEASURED: `/portforward/22/tcp` and `/portforward/2222/tcp` authorize IDENTICALLY, because
// kube-apiserver drops the port segment before the access review. RBAC cannot restrict the port. So
// the literal below is the ONLY limit that exists, and losing it turns a VM console into a general
// TCP tunnel into a customer's private machine network: every port on every VM the pass names.
//
// Five layers defend it, four of which fail a build:
//
//  1. The pass's vm target has no port field, and the decoder refuses unknown fields, so no pass can
//     carry one (internal/pass).
//  2. SubresourcePath takes the KIND and nothing else. There is no parameter to pass a port through.
//  3. The caller re-validates ns and name against the shapes below, so a name cannot continue the
//     path.
//  4. A table test asserting the exact URL by string equality, plus a fuzz test that never names the
//     constant, so it survives a refactor that renames or inlines it.
//  5. AssertSSHPortPinned panics immediately before the dial. A panic cannot be quietly swallowed by
//     a future edit; an error return can.
package kubevirt

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/runos-official/sessiongate/internal/pass"
)

// SSHPort is the only port a session may reach on a guest.
//
// DO NOT make this configurable, and do not thread it through a parameter. A configurable port is
// indistinguishable at runtime from an attacker-chosen one, and the access review cannot tell them
// apart either.
const SSHPort = 22

var (
	// One namespace per VM isolation group, and nothing else is addressable. Pinning the SHAPE is
	// what keeps kube-system, the gate's own namespace and every other cluster namespace
	// unreachable, without the gate carrying a denylist that a new namespace can outgrow.
	namespacePattern = regexp.MustCompile(`^vmgroup-[a-z0-9]{1,32}$`)
	// RFC 1123 label. No dots, so no traversal; no slashes, so no path injection.
	namePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

// SubresourcePath returns the KubeVirt subresource for a session kind.
//
// TAKES THE KIND AND NOTHING ELSE, DELIBERATELY. Do not add a parameter. The moment this function
// accepts a port, a namespace, a name or an options struct, the port pin becomes a value that flows
// from somewhere else, and every caller becomes a place to get it wrong.
func SubresourcePath(k pass.Kind) (string, error) {
	switch k {
	case pass.KindVMSerial:
		return "console", nil
	case pass.KindVMVNC:
		return "vnc", nil
	case pass.KindVMSSH:
		// The literal. See the file comment: RBAC cannot enforce this, so this string is the limit.
		return fmt.Sprintf("portforward/%d/tcp", SSHPort), nil
	default:
		return "", fmt.Errorf("%q is not a VM session kind", k)
	}
}

// Target is a validated VM session destination.
type Target struct {
	Namespace string
	Name      string
	Sub       string
}

// Resolve validates a pass's VM target and builds the subresource.
//
// The validation here is defence against a CONDUCTOR BUG, not against forgery: a forged pass never
// reaches this code because it fails the signature first. Conductor and the gate are separately
// deployed and separately versioned, and a conductor that started emitting "kube-system" must not
// become a session.
func Resolve(p *pass.Payload) (Target, error) {
	if p.VM == nil {
		return Target{}, fmt.Errorf("a %s pass carries no vm target", p.Kind)
	}
	if !namespacePattern.MatchString(p.VM.Namespace) {
		return Target{}, fmt.Errorf("namespace %q is not a VM group namespace", p.VM.Namespace)
	}
	if !namePattern.MatchString(p.VM.Name) {
		return Target{}, fmt.Errorf("machine name %q is not addressable", p.VM.Name)
	}
	sub, err := SubresourcePath(p.Kind)
	if err != nil {
		return Target{}, err
	}
	return Target{Namespace: p.VM.Namespace, Name: p.VM.Name, Sub: sub}, nil
}

// URL builds the absolute wss:// URL for a target against an apiserver host:port.
//
// Both caller-derived segments are PathEscaped even though both have already been matched against
// patterns that exclude every character escaping would change. That is not redundancy: it means a
// future loosening of a pattern cannot silently become a path injection, and the escape is the line
// a reader looks for.
func (t Target) URL(apiHost string) string {
	return fmt.Sprintf(
		"wss://%s/apis/subresources.kubevirt.io/v1/namespaces/%s/virtualmachineinstances/%s/%s",
		apiHost, url.PathEscape(t.Namespace), url.PathEscape(t.Name), t.Sub,
	)
}

// AssertSSHPortPinned panics if an SSH session is about to dial anything but port 22.
//
// CALLED IMMEDIATELY BEFORE THE DIAL, on the final string, after every transformation. Everything
// above can be refactored, inlined or "simplified"; this reads the bytes that are actually going out.
//
// A PANIC RATHER THAN AN ERROR, deliberately. An error return can be swallowed by a future edit that
// logs and continues, and the failure it guards against is silent by nature: a tunnel to port 3306
// works perfectly and looks like a working feature. The caller recovers at the session boundary, so
// this kills one session loudly instead of the pod.
func AssertSSHPortPinned(kind pass.Kind, dialURL string) {
	want := fmt.Sprintf("/portforward/%d/tcp", SSHPort)

	/*
	 * DECIDED BY KIND, NOT BY SEARCHING THE URL FOR A WORD.
	 *
	 * The first version asked `strings.Contains(dialURL, "portforward")`, and the VM NAME is
	 * interpolated into that same URL. So a customer who names a machine "portforward-test" made
	 * every serial and VNC session on it take the panic branch: the URL contained the word, the
	 * kind was not vm.ssh, and the guard fired on a session that was never a port-forward at all.
	 * Combined with a panic that leaked its hijacked socket, one badly-named VM was a denial of
	 * service against the whole cluster, reachable by its owner at no cost.
	 *
	 * The kind is the fact the URL is built FROM, so it is the fact to branch on. The suffix check
	 * then still reads the bytes actually going out, which is the point of doing this here.
	 */
	if kind == pass.KindVMSSH {
		if !strings.HasSuffix(dialURL, want) {
			panic(fmt.Sprintf(
				"session gate refuses to dial %q for kind %s: a port-forward session may only ever reach %s. "+
					"This is the only limit that exists, because kube-apiserver drops the port segment "+
					"before the access review and RBAC cannot restrict it.",
				dialURL, kind, want))
		}
		return
	}

	/*
	 * Any OTHER kind must not be dialling a port-forward at all. Matched on the whole trailing
	 * segment triple, so a VM merely NAMED "portforward" cannot trip it: the name is
	 * url.PathEscape'd, so its slashes are %2F and it can never contribute "/portforward/x/y" to
	 * the end of the path.
	 */
	if portForwardTail.MatchString(dialURL) {
		panic(fmt.Sprintf(
			"session gate refuses to dial %q for kind %s: only vm.ssh may open a port-forward, and only to %s.",
			dialURL, kind, want))
	}
}

// The trailing "/portforward/<port>/<protocol>" of a KubeVirt port-forward subresource.
var portForwardTail = regexp.MustCompile(`/portforward/[^/]+/[^/]+$`)

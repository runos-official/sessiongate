// Package workspace builds the one URL a workspace session is allowed to reach.
//
// A workspace pass carries no host, no URL, no scheme and no namespace. The gate knows where
// workspaces live. A pass that could name a host could name the gate's own address, another cluster
// service, or something outside the cluster entirely, and a signed pass naming an arbitrary host is
// a server-side request forgery with a signature on it.
package workspace

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/runos-official/sessiongate/internal/pass"
)

// Port is the workspace terminal's plain HTTP port inside the cluster. Fixed, like the SSH pin, and
// for the same reason: a configurable port is indistinguishable at runtime from an attacker-chosen
// one.
const Port = 7681

var (
	servicePattern = regexp.MustCompile(`^runostty-[a-z0-9-]{1,50}$`)
	// Exactly two logins exist inside a workspace image. An allowlist rather than a shape, because
	// the set is small, known, and closed.
	allowedUsers = map[string]bool{"dev": true, "devops": true}
)

// Target is a validated workspace destination.
type Target struct {
	Service   string
	Namespace string
	User      string
	Dir       string
	Cmd       string
}

// Resolve validates a pass's workspace target.
func Resolve(p *pass.Payload) (Target, error) {
	if p.WS == nil {
		return Target{}, fmt.Errorf("a %s pass carries no ws target", p.Kind)
	}
	if !servicePattern.MatchString(p.WS.Service) {
		return Target{}, fmt.Errorf("service %q is not a workspace service", p.WS.Service)
	}
	if !allowedUsers[p.WS.User] {
		return Target{}, fmt.Errorf("user %q is not a workspace login", p.WS.User)
	}
	if p.WS.Dir != "" {
		if !strings.HasPrefix(p.WS.Dir, "/") {
			return Target{}, fmt.Errorf("a working directory must be absolute")
		}
		if len(p.WS.Dir) > 512 {
			return Target{}, fmt.Errorf("the working directory is too long")
		}
		if strings.Contains(p.WS.Dir, "..") {
			return Target{}, fmt.Errorf("a working directory may not contain ..")
		}
	}
	if len(p.WS.Cmd) > 512 {
		return Target{}, fmt.Errorf("the command is too long")
	}
	return Target{
		Service: p.WS.Service, Namespace: "runos", User: p.WS.User,
		Dir: p.WS.Dir, Cmd: p.WS.Cmd,
	}, nil
}

// URL builds the in-cluster address of the workspace terminal.
//
// The host is BUILT from the service name and a fixed namespace, never taken from the pass, so the
// only thing a pass can influence is which workspace in this cluster it reaches.
func (t Target) URL(scheme, path string) string {
	u := url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s.%s.svc:%d", t.Service, t.Namespace, Port),
		Path:   path,
	}
	return u.String()
}

// Package replay makes a session pass single use.
//
// TWO LAYERS. An in-process set catches the common retry cheaply. The durable answer is a `create`
// of a Kubernetes Lease named from the pass's jti: a named create is a compare-and-set in etcd, so
// it survives a restart and a second replica with no call to the control plane and no new
// infrastructure.
//
// THREE RULES, EACH FROM AN ATTACK THAT SURVIVED ADVERSARIAL REFUTATION (2026-08-21). The first
// draft of the design named the mechanism and was silent on all three, and silence is where a
// fail-open lands.
//
//  1. FAIL CLOSED ON EVERY FAULT. 409 is "spent". Everything else, exhaustively, is "unavailable":
//     429 with or without Retry-After, any 5xx, a connection error, a deadline, a cancellation. Both
//     deny. No branch logs a warning and proceeds.
//  2. EXISTENCE DECIDES, AND THE LEASE IS WRITE-ONCE. A pass is spent if the object exists. Nothing
//     reads its contents to decide that, and NOTHING DELETES IT ON A FAILURE PATH. The tempting
//     cleanup is the hole: mint a pass for a stopped VM so the dial fails, and a gate that tidies up
//     on the error path has just made that pass replayable.
//  3. KUBERNETES DOES NOT DELETE AN EXPIRED LEASE, so the gate must. Measured on kind v1.36.1: a
//     Lease with leaseDurationSeconds 5 and a renewTime six years in the past was still present four
//     minutes later. leaseDurationSeconds is advisory for the holder protocol and is NOT a TTL.
//     Without a reaper the objects accumulate for ever, one per session, which is a slow denial of
//     service against the customer's own control plane.
//
// client-go is deliberately absent. The gate needs one create and one delete, no informers, no
// watches, and explicitly no leader election: that package renews and releases, which is the
// opposite of write-once. A direct client is a few hundred lines, keeps the image tiny, and makes
// the separate rate limit in rule 1 a separate http.Client rather than a configuration argument.
package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// The two outcomes a caller must distinguish, and the only two.
var (
	// ErrReplayed means this pass has been used. The client sent a real pass twice.
	ErrReplayed = errors.New("pass already spent")
	// ErrUnavailable means the claim could not be CONFIRMED. Deny. It is not "probably fine".
	ErrUnavailable = errors.New("single-use claim unavailable")
)

// ClaimTimeout bounds one claim.
//
// The deadline starts at CLAIM START, not at request start, so a slow WebSocket handshake cannot eat
// the budget and turn a healthy apiserver into an unavailable one.
const ClaimTimeout = 2 * time.Second

// Claimer burns a pass exactly once.
type Claimer interface {
	Claim(ctx context.Context, jti string, expiresAt time.Time) error
}

// --- the in-process layer ----------------------------------------------------------------------

// Memory is a best-effort front for the durable claim. It answers the common case, a client
// retrying with the same pass, without a round trip.
//
// IT IS NEVER THE ONLY ANSWER. It is per-process, so a second replica or a restart knows nothing,
// which is exactly why the Lease exists behind it.
type Memory struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewMemory() *Memory {
	return &Memory{seen: map[string]time.Time{}}
}

// Take records a jti and reports whether it was already present.
func (m *Memory) Take(jti string, expiresAt time.Time) (alreadySeen bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[jti]; ok {
		return true
	}
	m.seen[jti] = expiresAt
	return false
}

// Sweep drops entries whose pass has expired. They can never be presented again, so keeping them is
// only memory growth.
func (m *Memory) Sweep(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for jti, exp := range m.seen {
		if now.After(exp) {
			delete(m.seen, jti)
			removed++
		}
	}
	return removed
}

func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}

// --- the durable layer -------------------------------------------------------------------------

// LeaseClaimer creates one Lease per pass against the Kubernetes API.
type LeaseClaimer struct {
	// Base is the apiserver, e.g. https://10.96.0.1:443.
	Base string
	// Namespace holds the pass leases. One fixed namespace: a claim that could name its own
	// namespace is a claim two passes can avoid colliding in.
	Namespace string
	// Token is read fresh per call, because a projected service account token is rotated in place.
	Token func() (string, error)
	// HTTP is this claimer's OWN client with its own limits. Sharing the proxy client means a burst
	// of sessions starves the very call that decides replay.
	HTTP *http.Client
	// Now is injectable for tests.
	Now func() time.Time
}

// leaseObject carries METADATA AND NOTHING ELSE, on purpose.
//
// There is no Spec field, not even an empty one. Nothing reads a Lease's contents to decide whether
// a pass is spent, and a spec here would invite a later reader to consult holderIdentity or
// renewTime, which is rule 2 in reverse.
type leaseObject struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Metadata   leaseMeta `json:"metadata"`
}

type leaseMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// LeaseName is the object name for a pass.
//
// The jti is 32 lowercase hex by construction (the pass decoder refuses anything else), which is
// why it can be an object name at all: base64url carries '_' and mixed case, and an object name may
// carry neither. A jti that was not a legal name would make this create fail every time, and a
// single-use check that cannot run is a pass that can be replayed.
func LeaseName(jti string) string {
	return "pass-" + jti
}

// Claim creates the Lease, or reports why it could not.
//
// NOTHING HERE DELETES ANYTHING. There is no cleanup path, no rollback, no defer that removes the
// object if a later step fails. That is rule 2, and it is the difference between single use and
// "single use until something goes wrong".
func (c *LeaseClaimer) Claim(ctx context.Context, jti string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, ClaimTimeout)
	defer cancel()

	token, err := c.Token()
	if err != nil {
		// Cannot authenticate to the apiserver, so the claim cannot be confirmed. Deny.
		return fmt.Errorf("%w: reading the service account token: %v", ErrUnavailable, err)
	}

	body, err := json.Marshal(leaseObject{
		APIVersion: "coordination.k8s.io/v1",
		Kind:       "Lease",
		Metadata: leaseMeta{
			Name:      LeaseName(jti),
			Namespace: c.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "runos-session-gate",
				// The reaper reads this. It is a LABEL rather than spec.leaseDurationSeconds because
				// that field is advisory for the holder protocol and expires nothing.
				"runos.com/pass-expires-at": fmt.Sprintf("%d", expiresAt.Unix()),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("%w: building the claim: %v", ErrUnavailable, err)
	}

	endpoint := fmt.Sprintf("%s/apis/coordination.k8s.io/v1/namespaces/%s/leases",
		c.Base, url.PathEscape(c.Namespace))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: building the request: %v", ErrUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := c.HTTP.Do(req)
	if err != nil {
		// A connection error, a deadline, a cancellation. All three land here and all three deny.
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	// Drained so the connection can be reused, and bounded so an apiserver returning something
	// enormous cannot be used to make the gate allocate.
	drained, _ := io.ReadAll(io.LimitReader(res.Body, 8<<10))

	switch {
	case res.StatusCode == http.StatusCreated || res.StatusCode == http.StatusOK:
		return nil
	case res.StatusCode == http.StatusConflict:
		// The ONLY status that means "spent". Every other refusal is unavailability.
		return ErrReplayed
	default:
		// 401, 403, 404, 422, 429, every 5xx, and anything unforeseen. Named, not swallowed: an
		// operator seeing claim_unavailable needs the status to tell RBAC from an outage.
		return fmt.Errorf("%w: the apiserver answered %d: %s",
			ErrUnavailable, res.StatusCode, firstLine(drained))
	}
}

func firstLine(b []byte) string {
	const max = 200
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}

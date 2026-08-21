package replay

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingTransport answers with a canned response and records every request method and path, so a
// test can assert what the claimer did NOT do as well as what it did.
type recordingTransport struct {
	mu       sync.Mutex
	calls    []string
	status   int
	body     string
	err      error
	delay    time.Duration
	onCall   func(n int) (status int, body string)
	callSeen int
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.callSeen++
	n := r.callSeen
	r.calls = append(r.calls, req.Method+" "+req.URL.Path)
	r.mu.Unlock()

	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	status, body := r.status, r.body
	if r.onCall != nil {
		status, body = r.onCall(n)
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

func (r *recordingTransport) methods() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func claimer(rt *recordingTransport) *LeaseClaimer {
	return &LeaseClaimer{
		Base:      "https://10.96.0.1:443",
		Namespace: "runos",
		Token:     func() (string, error) { return "tok", nil },
		HTTP:      &http.Client{Transport: rt},
		Now:       time.Now,
	}
}

const jti = "0123456789abcdef0123456789abcdef"

func TestClaimSucceedsOnCreated(t *testing.T) {
	rt := &recordingTransport{status: http.StatusCreated, body: "{}"}
	if err := claimer(rt).Claim(context.Background(), jti, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("a 201 must be a successful claim, got %v", err)
	}
	if got := rt.methods(); len(got) != 1 || !strings.HasPrefix(got[0], "POST ") {
		t.Fatalf("expected exactly one POST, got %v", got)
	}
}

/**
 * THE FAULT MATRIX. Rule 1: 409 is spent, EVERYTHING else is unavailable, and both deny.
 *
 * Written as a table over the whole space rather than a few cases, because the failure this guards
 * against is a branch someone adds later for one status that "is probably fine".
 */
func TestEveryFaultDenies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rt     *recordingTransport
		expect error
	}{
		{"409 conflict is spent", &recordingTransport{status: http.StatusConflict, body: `{"reason":"AlreadyExists"}`}, ErrReplayed},
		{"429 throttled", &recordingTransport{status: http.StatusTooManyRequests, body: "slow down"}, ErrUnavailable},
		{"500", &recordingTransport{status: http.StatusInternalServerError, body: "boom"}, ErrUnavailable},
		{"503", &recordingTransport{status: http.StatusServiceUnavailable, body: "no"}, ErrUnavailable},
		{"401 unauthenticated", &recordingTransport{status: http.StatusUnauthorized, body: "no"}, ErrUnavailable},
		{"403 RBAC", &recordingTransport{status: http.StatusForbidden, body: "no"}, ErrUnavailable},
		{"404 namespace missing", &recordingTransport{status: http.StatusNotFound, body: "no"}, ErrUnavailable},
		{"422 rejected object", &recordingTransport{status: http.StatusUnprocessableEntity, body: "no"}, ErrUnavailable},
		{"connection error", &recordingTransport{err: errors.New("connection reset by peer")}, ErrUnavailable},
		{"a status nobody foresaw", &recordingTransport{status: 418, body: "?"}, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := claimer(tc.rt).Claim(context.Background(), jti, time.Now().Add(time.Minute))
			if !errors.Is(err, tc.expect) {
				t.Fatalf("expected %v, got %v", tc.expect, err)
			}
			// Whatever went wrong, the claimer must not have tried to tidy up.
			for _, call := range tc.rt.methods() {
				if strings.HasPrefix(call, "DELETE") {
					t.Fatalf("the claimer issued %s on a failure path; the Lease is write-once", call)
				}
			}
		})
	}
}

/** A hang past the deadline denies, and denies as unavailable rather than as spent. */
func TestClaimDeniesOnTimeout(t *testing.T) {
	rt := &recordingTransport{status: http.StatusCreated, body: "{}", delay: 3 * ClaimTimeout}
	start := time.Now()
	err := claimer(rt).Claim(context.Background(), jti, time.Now().Add(time.Minute))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a hang must deny as unavailable, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*ClaimTimeout {
		t.Fatalf("the claim ran %v, past its own %v budget", elapsed, ClaimTimeout)
	}
}

/**
 * The deadline starts at CLAIM START, not at request start.
 *
 * A parent context with plenty of time left must not be shortened, and one already near expiry must
 * not let the claim run longer than its own budget. Pinned because the natural refactor, passing the
 * request's context straight through, makes a slow handshake eat the claim's budget and turns a
 * healthy apiserver into an unavailable one.
 */
func TestClaimDeadlineIsItsOwn(t *testing.T) {
	rt := &recordingTransport{status: http.StatusCreated, body: "{}", delay: ClaimTimeout / 4}
	parent, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	if err := claimer(rt).Claim(parent, jti, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("a fast claim under a long parent must succeed, got %v", err)
	}
}

/** A token that cannot be read denies. It does not proceed unauthenticated. */
func TestClaimDeniesWhenTheTokenCannotBeRead(t *testing.T) {
	c := claimer(&recordingTransport{status: http.StatusCreated, body: "{}"})
	c.Token = func() (string, error) { return "", errors.New("no such file") }
	if err := c.Claim(context.Background(), jti, time.Now().Add(time.Minute)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}

/**
 * RULE 2, at this layer: the claimer has no delete path at all.
 *
 * Asserted over the whole sequence a real session takes, including the one that tempts a cleanup:
 * claim succeeds, then the thing the pass was for fails. The Lease must still be there.
 */
func TestNothingIsDeletedWhenTheSessionFails(t *testing.T) {
	rt := &recordingTransport{onCall: func(n int) (int, string) {
		if n == 1 {
			return http.StatusCreated, "{}"
		}
		return http.StatusConflict, `{"reason":"AlreadyExists"}` // the replay attempt
	}}
	c := claimer(rt)

	if err := c.Claim(context.Background(), jti, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// ... the caller's upstream dial fails here, and the caller does NOT get to undo the claim.
	if err := c.Claim(context.Background(), jti, time.Now().Add(time.Minute)); !errors.Is(err, ErrReplayed) {
		t.Fatalf("the same pass must be spent even though the session failed, got %v", err)
	}
	for _, call := range rt.methods() {
		if !strings.HasPrefix(call, "POST ") {
			t.Fatalf("the claimer issued %s; it may only ever create", call)
		}
	}
}

/** The name is derived so it is a legal object name, and it is stable. */
func TestLeaseName(t *testing.T) {
	if got := LeaseName(jti); got != "pass-"+jti {
		t.Fatalf("got %q", got)
	}
	if len(LeaseName(jti)) > 253 {
		t.Fatal("longer than a Kubernetes object name may be")
	}
}

// --- the memory layer --------------------------------------------------------------------------

func TestMemoryCatchesTheSecondUse(t *testing.T) {
	m := NewMemory()
	exp := time.Now().Add(time.Minute)
	if m.Take(jti, exp) {
		t.Fatal("the first use must not be seen")
	}
	if !m.Take(jti, exp) {
		t.Fatal("the second use must be seen")
	}
}

func TestMemorySweepsOnlyExpired(t *testing.T) {
	m := NewMemory()
	now := time.Now()
	m.Take("a", now.Add(-time.Second))
	m.Take("b", now.Add(time.Minute))
	if removed := m.Sweep(now); removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
	if m.Len() != 1 {
		t.Fatalf("expected 1 left, got %d", m.Len())
	}
	// The live one is still spent.
	if !m.Take("b", now.Add(time.Minute)) {
		t.Fatal("sweeping must not forget a pass that can still be presented")
	}
}

func TestMemoryIsConcurrencySafe(t *testing.T) {
	m := NewMemory()
	exp := time.Now().Add(time.Minute)
	const racers = 200
	var wg sync.WaitGroup
	var won int32
	var mu sync.Mutex
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			if !m.Take(jti, exp) {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("exactly one caller may win the race, %d did", won)
	}
}

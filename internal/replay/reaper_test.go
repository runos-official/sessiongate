package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

/**
 * THE STARTUP INVARIANT. A reaper whose window is shorter than a pass's life would make a spent pass
 * claimable again, so it must not be constructible at all.
 *
 * An error rather than a clamp: a clamp silently ignores what the operator configured, and this is
 * the setting where quietly doing something else is the dangerous outcome.
 */
func TestReaperRefusesAWindowThatWouldReopenReplay(t *testing.T) {
	for _, tc := range []struct{ retention, maxLife time.Duration }{
		{time.Minute, time.Minute},         // equal is not enough
		{30 * time.Second, time.Minute},    // shorter
		{0, time.Minute},                   // absent
		{5 * time.Minute, 5 * time.Minute}, // equal at the ws.files cap
	} {
		_, err := NewReaper("https://h", "runos", tok, http.DefaultClient, tc.retention, tc.maxLife)
		if err == nil {
			t.Errorf("retention %s with a %s pass lifetime was accepted", tc.retention, tc.maxLife)
		}
	}
	if _, err := NewReaper("https://h", "runos", tok, http.DefaultClient, time.Hour, 5*time.Minute); err != nil {
		t.Errorf("a window comfortably past the pass lifetime must be accepted: %v", err)
	}
}

func tok() (string, error) { return "t", nil }

type reaperTransport struct {
	mu      sync.Mutex
	items   []map[string]any
	deleted []string
	calls   []string
}

func (r *reaperTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.calls = append(r.calls, req.Method+" "+req.URL.Path+"?"+req.URL.RawQuery)
	defer r.mu.Unlock()

	if req.Method == http.MethodDelete {
		parts := strings.Split(req.URL.Path, "/")
		r.deleted = append(r.deleted, parts[len(parts)-1])
		return jsonResponse(http.StatusOK, "{}"), nil
	}
	body, _ := json.Marshal(map[string]any{"items": r.items})
	return jsonResponse(http.StatusOK, string(body)), nil
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func lease(name string, expiresAt time.Time) map[string]any {
	return map[string]any{"metadata": map[string]any{
		"name": name,
		"labels": map[string]string{
			"app.kubernetes.io/name":    "runos-session-gate",
			"runos.com/pass-expires-at": fmt.Sprintf("%d", expiresAt.Unix()),
		},
	}}
}

func TestReaperDeletesOnlyWhatCanNoLongerBePresented(t *testing.T) {
	now := time.Now()
	rt := &reaperTransport{items: []map[string]any{
		lease("pass-old", now.Add(-2*time.Hour)),       // long past retention
		lease("pass-recent", now.Add(-30*time.Second)), // expired, still inside retention
		lease("pass-live", now.Add(30*time.Second)),    // not even expired
	}}
	r, err := NewReaper("https://h", "runos", tok, &http.Client{Transport: rt}, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r.Now = func() time.Time { return now }

	deleted, err := r.ReapOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || len(rt.deleted) != 1 || rt.deleted[0] != "pass-old" {
		t.Fatalf("expected only pass-old to go, deleted=%d list=%v", deleted, rt.deleted)
	}
}

/** Scoped by label, so the gate can never eat a Lease it did not write. Several are load-bearing. */
func TestReaperListsOnlyItsOwnLeases(t *testing.T) {
	rt := &reaperTransport{}
	r, _ := NewReaper("https://h", "runos", tok, &http.Client{Transport: rt}, time.Hour, time.Minute)
	if _, err := r.ReapOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rt.calls) == 0 || !strings.Contains(rt.calls[0], "labelSelector") {
		t.Fatalf("the list must be label-scoped, got %v", rt.calls)
	}
	if !strings.Contains(rt.calls[0], "runos-session-gate") {
		t.Fatalf("the label selector must name the gate, got %v", rt.calls)
	}
}

/** A lease with no expiry label is left alone: deleting an object of unknown lifetime is how a
 * reaper eats something it should not have. */
func TestReaperLeavesUnlabelledLeasesAlone(t *testing.T) {
	rt := &reaperTransport{items: []map[string]any{
		{"metadata": map[string]any{"name": "pass-mystery", "labels": map[string]string{
			"app.kubernetes.io/name": "runos-session-gate",
		}}},
		{"metadata": map[string]any{"name": "pass-garbled", "labels": map[string]string{
			"app.kubernetes.io/name":    "runos-session-gate",
			"runos.com/pass-expires-at": "not-a-number",
		}}},
	}}
	r, _ := NewReaper("https://h", "runos", tok, &http.Client{Transport: rt}, time.Hour, time.Minute)
	deleted, err := r.ReapOnce(context.Background())
	if err != nil || deleted != 0 || len(rt.deleted) != 0 {
		t.Fatalf("expected nothing deleted, got %d %v err=%v", deleted, rt.deleted, err)
	}
}

/** Another replica reaping first is success, not an error worth alerting on. */
func TestReaperTreatsNotFoundAsDone(t *testing.T) {
	now := time.Now()
	rt := &notFoundOnDelete{items: []map[string]any{lease("pass-old", now.Add(-2*time.Hour))}}
	r, _ := NewReaper("https://h", "runos", tok, &http.Client{Transport: rt}, time.Hour, time.Minute)
	r.Now = func() time.Time { return now }
	if _, err := r.ReapOnce(context.Background()); err != nil {
		t.Fatalf("a lease already gone must not be an error: %v", err)
	}
}

type notFoundOnDelete struct{ items []map[string]any }

func (n *notFoundOnDelete) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodDelete {
		return jsonResponse(http.StatusNotFound, "{}"), nil
	}
	body, _ := json.Marshal(map[string]any{"items": n.items})
	return jsonResponse(http.StatusOK, string(body)), nil
}

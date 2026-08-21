package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Reaper deletes spent pass leases once they can no longer be presented.
//
// WHY IT HAS TO EXIST. Kubernetes DOES NOT DELETE AN EXPIRED LEASE. Measured on kind v1.36.1 during
// the design review: a Lease with leaseDurationSeconds 5 and a renewTime six years in the past was
// still present four minutes later and still counted in apiserver_storage_objects.
// leaseDurationSeconds is advisory for the holder protocol; it is not a TTL and nothing collects on
// it. Without this, the gate writes one object per session into a customer's etcd for ever, which is
// a slow denial of service against their own control plane.
//
// AND WHY ITS WINDOW IS AN INVARIANT. Reaping a lease makes its pass claimable again. If the
// retention were shorter than the longest a pass can live, there would be a window in which a spent
// pass is replayable, and the reaper itself would have opened it.
type Reaper struct {
	Base      string
	Namespace string
	Token     func() (string, error)
	HTTP      *http.Client
	// Retention is how long after a pass EXPIRES its lease is kept.
	Retention time.Duration
	Now       func() time.Time
}

// NewReaper refuses to build a reaper that could reopen replay.
//
// Returns an error rather than clamping. A clamp would silently ignore what an operator configured,
// and this is exactly the setting where "it quietly did something else" is the dangerous outcome.
// The caller exits non-zero on this, so the pod fails to start rather than running unsafely.
func NewReaper(base, namespace string, token func() (string, error), httpClient *http.Client,
	retention, maxPassLifetime time.Duration) (*Reaper, error) {
	if retention <= maxPassLifetime {
		return nil, fmt.Errorf(
			"lease retention (%s) must EXCEED the longest a pass can live (%s): reaping sooner than "+
				"a pass can be presented would make a spent pass claimable again, and the reaper "+
				"would be the thing that opened replay",
			retention, maxPassLifetime)
	}
	return &Reaper{
		Base: base, Namespace: namespace, Token: token, HTTP: httpClient,
		Retention: retention, Now: time.Now,
	}, nil
}

type leaseList struct {
	Metadata struct {
		// Continue is the apiserver's cursor. Empty means this was the last page.
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	} `json:"items"`
}

/*
pageSize bounds one list request.

WHY PAGINATION EXISTS HERE AT ALL. The first version listed every lease in ONE request and read the
body through an 8 MiB LimitReader, which returns a nil error on truncation. MEASURED against a fake
apiserver serving realistically shaped Lease objects (772 bytes each): 5,000 leases listed and
deleted fine; 12,000 produced a 9.26 MB body, silently truncated to 8 MiB, and failed with
"unexpected end of JSON input" BEFORE a single delete. So the reaper stopped collecting at exactly
the point it was most needed, and every later run failed the same way: the backlog could only grow,
which is the denial-of-service this component exists to prevent.
*/
const pageSize = 500

// ReapOnce deletes every lease whose pass expired more than Retention ago. Returns how many went.
//
// Errors are returned rather than swallowed, but a caller on a timer must log and continue: an
// unhandled failure on a ticker takes the process down, and a missed sweep is retried on the next
// tick.
func (r *Reaper) ReapOnce(ctx context.Context) (int, error) {
	token, err := r.Token()
	if err != nil {
		return 0, fmt.Errorf("reading the service account token: %w", err)
	}
	base := fmt.Sprintf("%s/apis/coordination.k8s.io/v1/namespaces/%s/leases",
		r.Base, url.PathEscape(r.Namespace))

	cutoff := r.Now().Add(-r.Retention)
	deleted := 0
	cursor := ""

	for {
		list, err := r.listPage(ctx, base, token, cursor)
		if err != nil {
			return deleted, err
		}

		for _, item := range list.Items {
			raw := item.Metadata.Labels["runos.com/pass-expires-at"]
			if raw == "" {
				// No expiry label means the gate cannot know when this became collectable, so it is
				// left alone. Deleting an object whose lifetime is unknown is how a reaper eats
				// something it should not have.
				continue
			}
			unix, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				continue
			}
			if !time.Unix(unix, 0).Before(cutoff) {
				continue
			}
			if err := r.delete(ctx, base, token, item.Metadata.Name); err != nil {
				return deleted, err
			}
			deleted++
		}

		cursor = list.Metadata.Continue
		if cursor == "" {
			return deleted, nil
		}
		// A cancelled context between pages must stop the walk rather than start another request.
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
	}
}

// listPage fetches one page of leases the gate wrote.
func (r *Reaper) listPage(ctx context.Context, base, token, cursor string) (*leaseList, error) {
	query := url.Values{}
	// Scoped by label, so the gate can never delete a lease it did not write. There are other Leases
	// in a cluster and several of them are load-bearing for the control plane itself.
	query.Set("labelSelector", "app.kubernetes.io/name=runos-session-gate")
	query.Set("limit", fmt.Sprintf("%d", pageSize))
	if cursor != "" {
		query.Set("continue", cursor)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	res, err := r.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	/*
	 * NO LimitReader, and that is the fix rather than a bigger number.
	 *
	 * io.ReadAll(io.LimitReader(body, n)) returns a NIL ERROR when it truncates, so an oversized
	 * page became invalid JSON and the reaper failed permanently with no hint of why. A page is
	 * bounded by `limit` above, which is a bound the APISERVER honours, so the body is bounded by
	 * construction rather than by a number this file guesses.
	 */
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading the lease list: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing leases: the apiserver answered %d: %s", res.StatusCode, firstLine(body))
	}

	var list leaseList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parsing the lease list: %w", err)
	}
	return &list, nil
}

// delete removes one lease. THE ONLY DELETE IN THIS PACKAGE, and it is reachable only from the
// reaper, never from a session path. See rule 2 in claim.go.
func (r *Reaper) delete(ctx context.Context, base, token, name string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, base+"/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 8<<10))
	switch res.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNotFound:
		// Not found is success: another replica reaped it first.
		return nil
	default:
		return fmt.Errorf("deleting lease %s: the apiserver answered %d", name, res.StatusCode)
	}
}

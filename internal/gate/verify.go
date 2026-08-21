// Package gate decides whether a request may open a session, and in what order it decides.
//
// THE ORDER IS THE SECURITY PROPERTY, not an implementation detail.
//
// Nothing reads a payload field for any purpose before the signature verifies. Everything decidable
// without trusting the caller is refused BEFORE the handshake with an HTTP status. Everything about
// the pass or the far end is a completed handshake plus a 4xxx close code, because a browser can
// read no body from a refused handshake: a client that gets a bare "connection failed" cannot tell
// an expired pass from a dead cluster, and will retry the wrong thing for ever.
package gate

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/runos-official/sessiongate/internal/kubevirt"
	"github.com/runos-official/sessiongate/internal/pass"
	"github.com/runos-official/sessiongate/internal/workspace"
)

// Close codes. The numbers are a contract with clients that already exist.
const (
	CloseDraining     = 4001 // the gate is shutting down, or the session was revoked
	ClosePassRefused  = 4401 // the pass was not acceptable, for ANY reason
	CloseWrongCluster = 4403 // right pass, wrong door: another cluster, or an origin mismatch
	CloseReplayed     = 4409 // the pass has been used
	CloseRateLimited  = 4429 // too many failed verifications from this source
	CloseNotFound     = 4404 // the far end does not exist
	CloseFarEnd       = 4502 // the far end refused or could not be reached
	CloseAtCapacity   = 4503 // the gate is full
)

// SessionProtocol is the subprotocol a client must offer. The PASS travels beside it as a second
// value, and the gate echoes only this one, so the pass never appears in a response header, in
// devtools, or in a proxy log that records response headers.
const SessionProtocol = "runos.session.v1"

// PassProtocolPrefix marks the subprotocol value carrying the pass.
const PassProtocolPrefix = "runos.pass."

// MaxPassBytes bounds the credential a client may present. See pass.MaxTokenBytes; this is the
// door's own limit, checked before anything parses.
const MaxPassBytes = 2048

/*
refusedText is the SAME for every cause of a 4401.

The gate must not be an oracle. Distinct messages for "expired", "bad signature" and "unknown key"
tell a prober which guess was closer, which is the whole game when someone is fishing for a valid
pass. An operator gets the real reason from the gate's own log, keyed by request id; the client gets
one sentence.
*/
const refusedText = "the session pass was refused"

// Decision is what the gate does with a request.
type Decision struct {
	// Allow is true when the request may proceed to the far end.
	Allow bool
	// HTTPStatus is set when the refusal happens BEFORE the handshake. Zero otherwise.
	HTTPStatus int
	// CloseCode is set when the refusal happens after a completed handshake. Zero otherwise.
	CloseCode int
	// ClientText is what the client is told. Bounded, and never more specific than it should be.
	ClientText string
	// LogReason is the real cause, for the gate's own log. Never sent to the client.
	LogReason string
	// Payload is set only when Allow is true.
	Payload *pass.Payload
}

func refusePre(status int, text, reason string) Decision {
	return Decision{HTTPStatus: status, ClientText: text, LogReason: reason}
}

func refuseClose(code int, text, reason string) Decision {
	// A WebSocket close reason is capped at 123 bytes by the protocol, and a longer one is a
	// protocol error rather than a truncated message, so it is bounded here and never allowed to
	// throw at write time.
	if len(text) > 123 {
		text = text[:123]
	}
	return Decision{CloseCode: code, ClientText: text, LogReason: reason}
}

// Config is what this gate knows about itself. All of it comes from the environment and the mounted
// ConfigMap, never from a request.
type Config struct {
	AID string
	CID string
	// Keys the gate trusts. Two during a rotation.
	Keys pass.Keys
	// AllowedOrigins is the console origins that may open a browser session. A request carrying NO
	// origin is a non-browser client and is not checked against this list.
	AllowedOrigins []string
	// Skew allowed between the control plane's clock and this cluster's.
	Skew time.Duration
}

// Request is the part of an inbound HTTP request the decision depends on.
type Request struct {
	Path         string
	RawQuery     string
	Origin       string
	Subprotocols []string
	// Kinds this door accepts. /v1/session takes the four stream kinds; the file endpoints take
	// ws.files and nothing else.
	AllowedKinds []pass.Kind
}

// Verify runs the checks in order and returns the first refusal, or an allow.
func Verify(req Request, cfg Config, now func() time.Time) Decision {
	// STEP 1: things decidable without touching the pass at all. Refused pre-handshake, because
	// there is nothing here a client needs a close code to understand.
	if req.RawQuery != "" {
		// A pass in a query string ends up in the ingress access log and the browser's history. The
		// gate refuses a query string entirely rather than ignoring it, so a client that tries is
		// told rather than silently working today and leaking.
		return refusePre(400, "this endpoint takes no query parameters", "query string present")
	}

	offered := 0
	token := ""
	for _, sp := range req.Subprotocols {
		if sp == SessionProtocol {
			offered++
			continue
		}
		if strings.HasPrefix(sp, PassProtocolPrefix) {
			token = strings.TrimPrefix(sp, PassProtocolPrefix)
		}
	}
	if offered == 0 {
		return refusePre(400, "offer the "+SessionProtocol+" subprotocol", "protocol not offered")
	}
	if token == "" {
		return refusePre(400, "no session pass was presented", "no pass subprotocol")
	}
	if len(token) > MaxPassBytes {
		return refusePre(400, "the session pass is too large", fmt.Sprintf("pass %d bytes", len(token)))
	}

	// STEPS 2 to 5: structure, signature, schema, lifetime. All inside pass.Verify, which refuses
	// before reading any field for a decision. Every cause collapses to ONE client message.
	p, err := pass.Verify(token, cfg.Keys, now, cfg.Skew)
	if err != nil {
		return refuseClose(ClosePassRefused, refusedText, "pass: "+err.Error())
	}

	// STEP 6: right pass, wrong door. Distinguishable from 4401 on purpose: this is almost always a
	// misconfigured client or a stale bookmark, and telling those apart from a bad pass is worth
	// more than the tiny amount it reveals, which is only that this gate is not that cluster.
	if p.AID != cfg.AID || p.CID != cfg.CID {
		return refuseClose(CloseWrongCluster, "this pass is for another cluster",
			fmt.Sprintf("pass names %s/%s, this gate is %s/%s", p.AID, p.CID, cfg.AID, cfg.CID))
	}

	// STEP 7: origin. ABSENT MEANS ABSENT, and that is not a hole. A browser always sends Origin on
	// a WebSocket upgrade; the CLI never does. Requiring one would break every non-browser client,
	// and treating an absent one as a match would let a browser omit it to bypass the check, which
	// a browser cannot do.
	if req.Origin != "" {
		if !originAllowed(req.Origin, cfg.AllowedOrigins) {
			return refuseClose(CloseWrongCluster, "this origin may not open a session",
				"origin "+safeOrigin(req.Origin)+" not in the allowlist")
		}
		if !sameOrigin(req.Origin, p.Org) {
			// The pass records the surface it was minted for. A pass minted for the console and
			// presented from somewhere else is a stolen pass being used from another page.
			return refuseClose(CloseWrongCluster, "this origin may not open a session",
				"origin "+safeOrigin(req.Origin)+" does not match the pass")
		}
	}

	// STEP 8: is this kind allowed at THIS door, and does the kind agree with the target block?
	// The second half is re-checked here as well as in the decoder because the two are separately
	// maintained and this is the last place before the target is built.
	if !kindAllowed(p.Kind, req.AllowedKinds) {
		return refuseClose(ClosePassRefused, refusedText,
			fmt.Sprintf("kind %s is not served at %s", p.Kind, req.Path))
	}

	// STEP 9: the target itself. Defence against a CONDUCTOR BUG rather than against forgery, since
	// a forged pass never reaches here. Logged at error, because reaching it means the control plane
	// emitted something it should never emit.
	if p.Kind.IsVM() {
		if _, err := kubevirt.Resolve(p); err != nil {
			return refuseClose(ClosePassRefused, refusedText, "TARGET REFUSED (conductor bug?): "+err.Error())
		}
	} else {
		if _, err := workspace.Resolve(p); err != nil {
			return refuseClose(ClosePassRefused, refusedText, "TARGET REFUSED (conductor bug?): "+err.Error())
		}
	}

	return Decision{Allow: true, Payload: p}
}

func kindAllowed(k pass.Kind, allowed []pass.Kind) bool {
	for _, a := range allowed {
		if a == k {
			return true
		}
	}
	return false
}

/*
originAllowed compares SCHEME AND HOST, never a prefix.

A prefix or suffix comparison is the classic origin bug: "https://console.runos.com.evil.test"
starts with the allowed value, and "https://evil-console.runos.com" ends with it. Both are parsed
and compared whole here.
*/
func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if sameOrigin(origin, a) {
			return true
		}
	}
	return false
}

func sameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil || ua.Host == "" {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil || ub.Host == "" {
		return false
	}
	// Scheme and host, both. Port is part of Host and is compared with it, because
	// https://example.com and https://example.com:8443 are different origins to a browser too.
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// safeOrigin bounds attacker text before it reaches a log line.
func safeOrigin(s string) string {
	const max = 128
	if len(s) > max {
		s = s[:max] + "..."
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			b.WriteByte('?')
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

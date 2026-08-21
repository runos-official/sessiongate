// Package pass decodes and verifies a RunOS session pass.
//
// A pass is the whole authorization for one interactive session. The gate verifies it locally with
// a public key and never calls the control plane, so everything the gate is allowed to do has to be
// inside the signed bytes and nowhere else.
//
// WIRE FORM
//
//	runos_pass_v1.<b64url_unpadded(payload JSON)>.<b64url_unpadded(signature)>
//
// The signature covers the ASCII bytes "runos_pass_v1.<payload segment>" EXACTLY AS TRANSMITTED,
// prefix included. Two consequences, both deliberate:
//
//   - There is no canonicalisation problem between Node and Go. Neither side re-serialises the
//     payload before signing or verifying, so a difference in key order, spacing or number
//     formatting between the two JSON writers cannot change the signed bytes.
//   - A future v2 pass cannot be replayed as v1, because the version prefix is inside the
//     signature rather than beside it.
//
// UNPADDED base64url is not a style choice. The pass travels as a WebSocket subprotocol value,
// which must be an RFC 7230 token, and '=', '+' and '/' are not token characters. Measured
// 2026-08-21: Chrome, Safari and Firefox all throw SyntaxError from the WebSocket constructor
// before any request is sent, so a padded pass fails with an empty server log and a useless client
// error.
//
// The algorithm is Ed25519, fixed, and appears nowhere in the token. A negotiable "alg" is the most
// common way this shape gets broken, and no JWT library is used on either side.
package pass

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Prefix is the first segment, and it is part of the signed bytes.
const Prefix = "runos_pass_v1"

// MaxTokenBytes bounds a pass before anything expensive touches it.
//
// A real pass is a few hundred bytes. The cap exists because the token arrives in a header or a
// subprotocol value that a client controls the length of, and base64-decoding then Ed25519-verifying
// a megabyte per request is a cheap amplifier for the caller and an expensive one for the gate.
const MaxTokenBytes = 4096

// The bounds on the free text a workspace session carries. The SAME numbers are enforced by
// conductor at mint time, so a caller is told at request time rather than at connect time.
const (
	MaxWorkspaceDirBytes = 512
	MaxWorkspaceCmdBytes = 512
)

// decodeSegment decodes unpadded base64url STRICTLY.
//
// base64.RawURLEncoding on its own accepts a final character whose unused low bits are not zero:
// two different segment strings then decode to the same bytes. That is harmless for THIS design,
// because the signature covers the segment text rather than the decoded bytes, so a rewritten tail
// simply fails the signature. It is not harmless for AGREEMENT: conductor's decoder round-trips and
// refuses the same input as malformed, so without .Strict() the two implementations refuse one input
// with two different codes, and a client branching on the code sees a different fault depending on
// which side answered. Strict here, round-trip there, one verdict.
func decodeSegment(segment string) ([]byte, error) {
	// THE ALPHABET IS CHECKED BEFORE THE DECODER, and this is not belt and braces.
	//
	// MEASURED 2026-08-21, and it survived .Strict(): Go's encoding/base64 IGNORES '\r' and '\n' by
	// documented design, at every strictness. So "<valid pass>\r\n" decoded to the same bytes,
	// verified, and was ACCEPTED. Two consequences, both bad. It is a DIFFERENT STRING that opens
	// the same session, which defeats any replay cache keyed on the token text and any log line an
	// operator greps for. And conductor refuses it, so the two implementations disagreed about one
	// input, which is the whole thing the shared vectors exist to prevent.
	//
	// Rejecting the character set first removes newline-skipping and anything else the decoder is
	// lenient about, and it is the same check conductor makes.
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return nil, errors.New("segment contains a character that is not unpadded base64url")
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(segment)
}

// Kind is what sort of session a pass authorizes. The kind is SIGNED, and everything that varies by
// kind (which target block is present, the lifetime cap, whether it is a websocket at all) derives
// from it. There is deliberately no separate policy field: a second field saying what the kind
// already says is a second thing to get out of step.
type Kind string

const (
	KindVMSSH      Kind = "vm.ssh"
	KindVMSerial   Kind = "vm.serial"
	KindVMVNC      Kind = "vm.vnc"
	KindWSTerminal Kind = "ws.terminal"
	KindWSFiles    Kind = "ws.files"
)

// IsVM reports whether this kind targets a virtual machine rather than a workspace.
func (k Kind) IsVM() bool {
	return k == KindVMSSH || k == KindVMSerial || k == KindVMVNC
}

func (k Kind) valid() bool {
	return k.IsVM() || k == KindWSTerminal || k == KindWSFiles
}

// MaxLifetime is the longest exp-iat span this kind may carry.
//
// The gate applies this ITSELF rather than trusting the signed exp alone. A control-plane bug that
// mints a pass good for a day must not produce a credential good for a day, and the component that
// enforces the limit should be the one holding the door.
func (k Kind) MaxLifetime() time.Duration {
	if k == KindWSFiles {
		// A file listing or download is a series of separate HTTP requests rather than one long
		// stream, so it needs a window rather than an instant.
		return 300 * time.Second
	}
	return 60 * time.Second
}

// VMTarget is the whole address of a virtual machine session. There is no port field and there
// never will be: vm.ssh always reaches port 22, and the port is compiled into the gate. A pass that
// could name a port is a general tunnel into a customer's private network wearing a console's
// clothes.
type VMTarget struct {
	Namespace string `json:"ns"`
	Name      string `json:"name"`
}

// WSTarget is the whole address of a workspace session. There is no host, URL, scheme or namespace:
// the gate knows where workspaces live, and a pass that could name a host could name the gate's own
// address or another cluster service.
type WSTarget struct {
	Service string `json:"svc"`
	UID     string `json:"uid"`
	User    string `json:"user"`
	Dir     string `json:"dir"`
	Cmd     string `json:"cmd"`
}

// Payload is the signed body. Every field is required. Unknown fields are refused, which is what
// stops an attacker adding a "port" and hoping something downstream reads it.
type Payload struct {
	V   int    `json:"v"`
	KID string `json:"kid"`
	JTI string `json:"jti"`
	// RawMessage, not json.Number, and the difference is a real divergence rather than taste.
	// MEASURED 2026-08-21 by the shared vectors: Go's encoding/json happily decodes the JSON
	// STRING "1755800060" into a json.Number, because json.Number's underlying kind is string.
	// JavaScript's `typeof exp === "number"` refuses the same payload. One side accepting what
	// the other refuses is precisely the hole a single shared vector file exists to find.
	// RawMessage keeps the literal bytes, so a quoted number is visible as quoted.
	IAT  json.RawMessage `json:"iat"`
	EXP  json.RawMessage `json:"exp"`
	AID  string          `json:"aid"`
	CID  string          `json:"cid"`
	Sub  string          `json:"sub"`
	Kind Kind            `json:"kind"`
	Org  string          `json:"org"`
	VM   *VMTarget       `json:"vm,omitempty"`
	WS   *WSTarget       `json:"ws,omitempty"`
}

// IssuedAt and ExpiresAt are the parsed times. Validation has already refused anything that is not
// a whole second count, so these cannot fail here.
func (p *Payload) IssuedAt() time.Time  { n, _ := wholeSeconds(p.IAT); return time.Unix(n, 0).UTC() }
func (p *Payload) ExpiresAt() time.Time { n, _ := wholeSeconds(p.EXP); return time.Unix(n, 0).UTC() }

// Refusal codes. Deliberately few.
//
// A taxonomy of forty codes is worse than eight: nobody keys on the rare ones, the client cannot
// branch usefully, and each extra code is another chance for two implementations to disagree about
// which one applies. These are the distinctions a CALLER can act on.
const (
	ErrMalformed    = "pass_malformed"     // not three segments, wrong prefix, bad base64, bad signature length
	ErrPayload      = "pass_payload"       // not an object, unknown field, missing field, wrong type, duplicate key
	ErrUnknownKey   = "pass_unknown_key"   // kid names no key this gate holds
	ErrBadSignature = "pass_bad_signature" // the bytes do not verify under the named key
	ErrTarget       = "pass_target"        // kind and target block disagree, or the target is not addressable
	ErrExpired      = "pass_expired"       // exp is in the past, or iat is in the future
	ErrLifetime     = "pass_lifetime"      // exp-iat exceeds what this kind may carry
)

// Error is a refusal with a stable code and a human reason.
//
// The code travels WITH the reason on purpose: a refusal whose message says one thing while its
// code says another sends a client branching on the code somewhere the prose does not.
type Error struct {
	Code   string
	Reason string
}

func (e *Error) Error() string { return e.Code + ": " + e.Reason }

func refuse(code, format string, args ...any) error {
	return &Error{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// CodeOf returns the refusal code for an error, or "" if it is not a refusal.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Keys maps a key id to the public half. One keypair per cluster, with room for a second during
// rotation: the gate must be able to hold the outgoing and incoming key at once, or every rotation
// is an outage.
type Keys map[string]ed25519.PublicKey

// Now is the clock, injectable so tests do not sleep.
type Now func() time.Time

// Verify decodes a pass, checks its signature against the key its kid names, and validates every
// field. It returns the payload only when all of that passes.
//
// ORDER MATTERS AND IS DELIBERATE: structure, then signature, THEN semantics. Nothing that comes
// out of an unverified payload is used to make a decision, including which key to trust beyond the
// kid lookup itself, and no error message quotes unverified content back in a form that could be
// mistaken for a fact about the caller.
func Verify(token string, keys Keys, now Now, skew time.Duration) (*Payload, error) {
	if now == nil {
		now = time.Now
	}

	// SIZE FIRST, before base64 and long before Ed25519. A pass is a few hundred bytes; anything
	// approaching this is either broken or an attempt to make the gate spend a decode and a
	// signature check per megabyte of header. The cheapest possible check goes first.
	if len(token) > MaxTokenBytes {
		return nil, refuse(ErrMalformed, "a pass is at most %d bytes, this is %d", MaxTokenBytes, len(token))
	}

	raw, sig, err := split(token)
	if err != nil {
		return nil, err
	}

	payloadBytes, err := decodeSegment(raw.payloadSegment)
	if err != nil {
		return nil, refuse(ErrMalformed, "the payload segment is not canonical unpadded base64url")
	}

	p, err := decodePayload(payloadBytes)
	if err != nil {
		return nil, err
	}

	// The kid's SHAPE is checked before the lookup, and it is the one piece of semantics that runs
	// on unverified bytes. It has to: the lookup needs a key id, and "unknown key" and "malformed
	// pass" send an operator to opposite places. An unknown kid means a rotation this gate has not
	// seen; a 6-character kid means the minting side is broken. The check reveals nothing and
	// decides nothing beyond which refusal to name.
	if err := hexField("kid", p.KID, 16); err != nil {
		return nil, err
	}

	key, ok := keys[p.KID]
	if !ok {
		// Says nothing about which keys ARE held. An unknown kid is either a rotation the gate has
		// not seen or an attacker guessing, and neither is helped by an inventory.
		return nil, refuse(ErrUnknownKey, "no key with id %q", safeEcho(p.KID))
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, refuse(ErrUnknownKey, "the key with id %q is not a usable Ed25519 public key", safeEcho(p.KID))
	}

	if !ed25519.Verify(key, raw.signed, sig) {
		return nil, refuse(ErrBadSignature, "the signature does not verify under key %q", safeEcho(p.KID))
	}

	// Everything past this line is trusted bytes.
	if err := p.validate(now(), skew); err != nil {
		return nil, err
	}
	return p, nil
}

type parts struct {
	payloadSegment string
	// signed is the exact ASCII the signature covers: prefix, dot, payload segment.
	signed []byte
}

func split(token string) (parts, []byte, error) {
	// SplitN with 4 rather than Split, so a fourth segment is a refusal instead of being ignored.
	// A trailing ".<anything>" that the verifier drops is a way to smuggle bytes past a logger or a
	// proxy that reads the whole value.
	seg := strings.SplitN(token, ".", 4)
	if len(seg) != 3 {
		return parts{}, nil, refuse(ErrMalformed, "a pass has exactly three dot-separated segments, this has %d", len(seg))
	}
	if seg[0] != Prefix {
		return parts{}, nil, refuse(ErrMalformed, "a pass starts with %q", Prefix)
	}
	if seg[1] == "" || seg[2] == "" {
		return parts{}, nil, refuse(ErrMalformed, "a pass has no empty segments")
	}
	sig, err := decodeSegment(seg[2])
	if err != nil {
		return parts{}, nil, refuse(ErrMalformed, "the signature segment is not canonical unpadded base64url")
	}
	if len(sig) != ed25519.SignatureSize {
		// Checked before ed25519.Verify, which would return false for a short signature anyway. The
		// distinction matters for the operator: a 63-byte signature is a truncation somewhere in
		// the transport, not an attacker.
		return parts{}, nil, refuse(ErrMalformed, "an Ed25519 signature is %d bytes, this is %d", ed25519.SignatureSize, len(sig))
	}
	return parts{
		payloadSegment: seg[1],
		signed:         []byte(Prefix + "." + seg[1]),
	}, sig, nil
}

// decodePayload parses the payload with every strictness the two languages can agree on.
func decodePayload(b []byte) (*Payload, error) {
	if err := rejectDuplicateKeys(b); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	// UseNumber keeps iat and exp as their literal text, so "1755800000.0" and "1.7558e9" can be
	// refused for what they are rather than silently becoming an integer. Go and JavaScript disagree
	// about large and fractional numbers, and this is where that disagreement would live.
	dec.UseNumber()

	var p Payload
	if err := dec.Decode(&p); err != nil {
		return nil, refuse(ErrPayload, "the payload is not a valid pass body")
	}
	// A second value after the object: "{...}{...}" or "{...}garbage". Decode stops at the first,
	// and the rest would be bytes the signature covered that nothing ever looked at.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, refuse(ErrPayload, "the payload has trailing content after the object")
	}
	return &p, nil
}

// rejectDuplicateKeys refuses a payload containing the same key twice at any level.
//
// WHY, and it is the single most important line in this file for cross-language safety. Both Go and
// JavaScript keep the LAST value for a duplicated key today, so they happen to agree. That
// agreement is incidental, unspecified by JSON itself, and true of neither every parser nor
// necessarily every future version. A payload like {"kind":"ws.files","kind":"vm.ssh"} where one
// side reads one value and the other reads the other is a forgery that verifies. Refusing the shape
// entirely costs nothing and removes the class.
func rejectDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return refuse(ErrPayload, "the payload is not valid JSON")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		// An array, a string, a number or a bare null. All valid JSON, none of them a pass body.
		return refuse(ErrPayload, "the payload is not a JSON object")
	}
	if err := walkObject(dec); err != nil {
		return err
	}
	return nil
}

func walkObject(dec *json.Decoder) error {
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return refuse(ErrPayload, "the payload is not valid JSON")
		}
		key, ok := tok.(string)
		if !ok {
			return refuse(ErrPayload, "the payload is not valid JSON")
		}
		if seen[key] {
			return refuse(ErrPayload, "the payload names %q more than once", safeEcho(key))
		}
		seen[key] = true
		if err := walkValue(dec); err != nil {
			return err
		}
	}
	// Consume the closing brace.
	if _, err := dec.Token(); err != nil {
		return refuse(ErrPayload, "the payload is not valid JSON")
	}
	return nil
}

func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return refuse(ErrPayload, "the payload is not valid JSON")
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		return walkObject(dec)
	case '[':
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return refuse(ErrPayload, "the payload is not valid JSON")
		}
		return nil
	}
	return nil
}

// validate checks the semantics of an already-verified payload.
//
// Called ONLY after the signature verifies. Doing it earlier would mean spending work on attacker
// bytes and, worse, producing precise error messages about the contents of an unsigned blob.
func (p *Payload) validate(now time.Time, skew time.Duration) error {
	if p.V != 1 {
		return refuse(ErrPayload, "this is a version %d pass and this gate reads version 1", p.V)
	}
	// kid was checked before the key lookup in Verify, which is the only place it can be checked,
	// so it is deliberately not repeated here.
	if err := hexField("jti", p.JTI, 32); err != nil {
		return err
	}
	for _, f := range []struct{ name, value string }{
		{"aid", p.AID}, {"cid", p.CID}, {"sub", p.Sub}, {"org", p.Org},
	} {
		if f.value == "" {
			return refuse(ErrPayload, "%s is required", f.name)
		}
		if !printableASCII(f.value) {
			// Homoglyphs and unicode normalisation are a real path to "the same" subject id being
			// two different strings in two places. Every one of these fields is machine-generated
			// and ASCII by construction, so refusing anything else costs nothing real.
			return refuse(ErrPayload, "%s must be printable ASCII", f.name)
		}
	}
	if !p.Kind.valid() {
		return refuse(ErrPayload, "%q is not a session kind", safeEcho(string(p.Kind)))
	}

	iat, ok := wholeSeconds(p.IAT)
	if !ok {
		return refuse(ErrPayload, "iat must be a whole number of seconds")
	}
	exp, ok := wholeSeconds(p.EXP)
	if !ok {
		return refuse(ErrPayload, "exp must be a whole number of seconds")
	}
	if iat <= 0 || exp <= 0 {
		return refuse(ErrPayload, "iat and exp must be positive")
	}
	if exp <= iat {
		// Equal is refused as well as inverted. A pass that expires at the instant it was issued is
		// either a bug or an attempt to make the lifetime cap arithmetic underflow.
		return refuse(ErrLifetime, "exp must be after iat")
	}
	/*
	 * COMPARED IN SECONDS, NOT AS A DURATION, and the difference is a real hole rather than taste.
	 *
	 * `time.Duration(exp-iat) * time.Second` computes NANOSECONDS in an int64, which wraps above a
	 * span of 9223372036 seconds. MEASURED: span 9223372036 was refused, span 9223372037 was
	 * ACCEPTED, and so was a span putting the expiry in the year 2570, because the multiply produced
	 * a negative or tiny value that sailed past the cap. The check whose whole purpose is that a
	 * buggy or compromised control plane cannot mint a long-lived credential did not exist for
	 * exactly that case. Conductor's TypeScript mirror refuses all of them, so it was a divergence
	 * too.
	 *
	 * Seconds are compared as plain integers, which cannot overflow for any value the decoder
	 * accepts, and the vectors now cross the boundary in both directions.
	 */
	capSeconds := int64(p.Kind.MaxLifetime() / time.Second)
	if life := exp - iat; life > capSeconds {
		return refuse(ErrLifetime, "a %s pass may live %d seconds, this one claims %d",
			p.Kind, capSeconds, life)
	}

	// Skew is applied at BOTH ends and is small. The cluster and the control plane are different
	// machines, and a pass minted 60 seconds long dies before it is used if the cluster's clock
	// runs a minute fast.
	if now.After(time.Unix(exp, 0).Add(skew)) {
		return refuse(ErrExpired, "this pass expired")
	}
	if now.Before(time.Unix(iat, 0).Add(-skew)) {
		return refuse(ErrExpired, "this pass is not valid yet")
	}

	return p.validateTarget()
}

// validateTarget is the tenancy and target-confusion boundary.
//
// The gate builds a KubeVirt subresource URL out of these strings, so anything that could carry a
// slash, a dot-dot, or a query string is a path-injection vector: a "name" of
// "vm-abcde/portforward/22/tcp" or "../../kube-system/x" turns a console into something else. The
// checks are allowlists rather than denylists, because a denylist of encodings is a game nobody
// wins.
func (p *Payload) validateTarget() error {
	switch {
	case p.VM != nil && p.WS != nil:
		// Both blocks present is never legitimate, and the interesting version is a pass whose kind
		// says ws.files while a vm block rides along for whatever reads it first.
		return refuse(ErrTarget, "a pass carries exactly one target, this has both vm and ws")
	case p.VM == nil && p.WS == nil:
		return refuse(ErrTarget, "a pass carries a target, this has neither vm nor ws")
	case p.Kind.IsVM() && p.VM == nil:
		return refuse(ErrTarget, "a %s pass carries a vm target", p.Kind)
	case !p.Kind.IsVM() && p.WS == nil:
		return refuse(ErrTarget, "a %s pass carries a ws target", p.Kind)
	}

	if p.VM != nil {
		// The namespace shape is fixed by RunOS: one namespace per VM isolation group. Pinning it
		// to that shape is what stops a signed pass naming kube-system, the gate's own namespace,
		// or any other cluster namespace, WITHOUT the gate needing a list of forbidden names.
		if !vmGroupNamespace(p.VM.Namespace) {
			return refuse(ErrTarget, "%q is not a VM group namespace", safeEcho(p.VM.Namespace))
		}
		if !k8sName(p.VM.Name) {
			return refuse(ErrTarget, "%q is not a machine name", safeEcho(p.VM.Name))
		}
		return nil
	}

	if p.WS.Service == "" || p.WS.UID == "" || p.WS.User == "" {
		return refuse(ErrTarget, "a ws target names svc, uid and user")
	}
	if !k8sName(p.WS.Service) {
		return refuse(ErrTarget, "%q is not a workspace service name", safeEcho(p.WS.Service))
	}
	if !printableASCII(p.WS.UID) || !printableASCII(p.WS.User) {
		return refuse(ErrTarget, "a ws target's uid and user must be printable ASCII")
	}
	/*
	 * ONE LIMIT, and it is the same number at every hop.
	 *
	 * These were 1024 and 4096 here, 1024 and 4096 in conductor's route, and 512 and 512 in the
	 * gate's own workspace resolver. So conductor happily returned 201 for a pass the gate could
	 * never serve, and the client got a generic refusal at connect time for a request that was
	 * accepted at mint time. Worse, a 4096-character cmd produced a token LARGER than MaxTokenBytes,
	 * which every verifier then refused as malformed: conductor could mint a credential that
	 * violated its own size cap.
	 *
	 * 512 is the tightest of the three and leaves the whole token comfortably inside MaxTokenBytes.
	 */
	if len(p.WS.Dir) > MaxWorkspaceDirBytes || len(p.WS.Cmd) > MaxWorkspaceCmdBytes {
		return refuse(ErrTarget, "the ws target's dir or cmd is too long")
	}
	if !printableASCIIOrEmpty(p.WS.Dir) {
		return refuse(ErrTarget, "the ws target's dir must be printable ASCII")
	}
	return nil
}

func hexField(name, value string, want int) error {
	if len(value) != want {
		return refuse(ErrPayload, "%s is %d lowercase hex characters, this is %d", name, want, len(value))
	}
	// hex.DecodeString accepts uppercase, so the case check is separate. jti becomes a Kubernetes
	// object name, which must be lowercase, and a kid that differs only in case would be a second
	// name for one key.
	if value != strings.ToLower(value) {
		return refuse(ErrPayload, "%s is lowercase hex", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return refuse(ErrPayload, "%s is lowercase hex", name)
	}
	return nil
}

// wholeSeconds accepts only a bare integer literal: no quotes, no exponent, no decimal point, no
// leading plus.
//
// It reads the RAW BYTES rather than a decoded value, so "1.7558e9", 1755800000.0 and the JSON
// string "1755800060" are each visible as what they are. JavaScript and Go disagree about all three,
// in different directions, and this is where that disagreement is settled.
func wholeSeconds(raw json.RawMessage) (int64, bool) {
	s := string(raw)
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '-' && i == 0 {
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	// Refuse a leading zero: "0755800000" is octal to a human reader and decimal to both parsers,
	// and a number with two readings has no place in a credential.
	if len(s) > 1 && (s[0] == '0' || (s[0] == '-' && s[1] == '0')) {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func printableASCII(s string) bool {
	if s == "" {
		return false
	}
	return printableASCIIOrEmpty(s)
}

func printableASCIIOrEmpty(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// vmGroupNamespace matches the one namespace shape a VM session may name.
func vmGroupNamespace(s string) bool {
	const prefix = "vmgroup-"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	return lowerAlnum(s[len(prefix):], 1, 63-len(prefix))
}

// k8sName is the RFC 1123 label shape Kubernetes uses for object names: lowercase alphanumerics and
// dashes, starting and ending alphanumeric. No dots, so no traversal, and no slashes, so no path
// injection into a subresource URL.
func k8sName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return false
	}
	return true
}

func lowerAlnum(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// safeEcho bounds and sanitises attacker-controlled text before it reaches an error string.
//
// Refusals are logged and shown, and a 4 KB field or one carrying control characters turns a log
// line into a mess or, with the right terminal escape, into something that lies to whoever reads
// it.
func safeEcho(s string) string {
	const max = 64
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			b.WriteByte('?')
			continue
		}
		b.WriteByte(c)
	}
	if len(s) > max {
		b.WriteString("...")
	}
	return b.String()
}

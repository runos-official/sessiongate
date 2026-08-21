package pass

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// Sign produces a pass over an already-built payload.
//
// THE GATE NEVER CALLS THIS. The private half of a cluster's keypair never leaves the control
// plane, and a gate that could sign could mint itself a session for anything. It lives here because
// the golden vectors have to be generated from a fixed test key, and because the cross-language
// check runs both ways: conductor mints and Go verifies, and Go mints and conductor verifies. A
// signer that only one side has is a signer whose disagreements are invisible.
//
// Marshalling here uses encoding/json's field order, which differs from what conductor's TypeScript
// will produce. That difference is harmless BY DESIGN: the signature covers the bytes exactly as
// transmitted, so neither side re-serialises the other's payload. Any test that assumes byte
// equality between the two implementations is testing the wrong thing.
func Sign(p *Payload, kid string, key ed25519.PrivateKey) (string, error) {
	p.KID = kid
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return SignRaw(body, key), nil
}

// SignRaw signs payload bytes verbatim, without marshalling.
//
// This is what builds a malformed vector: a payload that is deliberately wrong (a duplicate key, an
// unknown field, a fractional exp) still needs a VALID signature, or the test proves only that the
// signature check runs first and never reaches the case it was written for.
func SignRaw(payload []byte, key ed25519.PrivateKey) string {
	segment := base64.RawURLEncoding.EncodeToString(payload)
	signed := []byte(Prefix + "." + segment)
	sig := ed25519.Sign(key, signed)
	return Prefix + "." + segment + "." + base64.RawURLEncoding.EncodeToString(sig)
}

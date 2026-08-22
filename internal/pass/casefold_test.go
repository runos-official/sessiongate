package pass

import (
	"strings"
	"testing"
)

/*
A CASE-VARIANT DUPLICATE IS A FORGERY THAT USED TO VERIFY.

Go's encoding/json matches struct tags case-insensitively, so `KIND` is a KNOWN field to
DisallowUnknownFields, and the duplicate check keyed on the exact string never saw the pair. The
last value won, so the gate decoded `vm.ssh` from a payload whose first `kind` said `ws.files`,
while both TypeScript verifiers refused the identical token. Same bytes, opposite verdicts, on the
only authorization boundary there is.

Not exploitable without the signing key, which the gate does not hold. It is fixed because the
golden vectors are the stated contract between the three implementations, and a contract that only
holds for byte-identical keys is not the one the header claims.
*/
func TestCaseVariantDuplicateKeysAreRefused(t *testing.T) {
	for _, body := range []string{
		`{"kind":"ws.files","KIND":"vm.ssh"}`,
		`{"sub":"me","SUB":"someone-else"}`,
		`{"exp":1,"EXP":9999999999}`,
		`{"vm":{"ns":"vmgroup-aaaaa","name":"mine"},"VM":{"ns":"vmgroup-bbbbb","name":"victim"}}`,
		`{"vm":{"ns":"vmgroup-aaaaa","NS":"vmgroup-bbbbb","name":"v"}}`,
	} {
		err := rejectDuplicateKeys([]byte(body))
		if err == nil {
			t.Errorf("accepted a case-variant duplicate: %s", body)
			continue
		}
		if !strings.Contains(err.Error(), "more than once") {
			t.Errorf("refused %s for the wrong reason: %v", body, err)
		}
	}
}

// The ordinary exact duplicate stays refused, and a legitimate body stays accepted.
func TestPlainDuplicatesStillRefusedAndCleanBodiesStillPass(t *testing.T) {
	if err := rejectDuplicateKeys([]byte(`{"kind":"a","kind":"b"}`)); err == nil {
		t.Error("an exact duplicate was accepted")
	}
	clean := `{"v":1,"kid":"a1b2c3d4e5f60718","jti":"0123456789abcdef0123456789abcdef",` +
		`"iat":1,"exp":2,"aid":"rjwrn","cid":"v6b","sub":"me","kind":"vm.ssh",` +
		`"org":"https://console.runos.com","vm":{"ns":"vmgroup-aaaaa","name":"v"}}`
	if err := rejectDuplicateKeys([]byte(clean)); err != nil {
		t.Errorf("a legitimate payload was refused: %v", err)
	}
}

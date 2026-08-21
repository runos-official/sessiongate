package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

/**
 * THE STARTUP INVARIANTS. Every one of these guards something whose failure mode is SILENT: a gate
 * that started anyway would serve sessions and look healthy while doing the wrong thing.
 *
 * They are tested as refusals rather than as documentation, because a documented option is an option
 * somebody sets.
 */

func withEnv(t *testing.T, kv map[string]string, fn func()) {
	t.Helper()
	saved := map[string]string{}
	for k, v := range kv {
		saved[k] = os.Getenv(k)
		if v == "" {
			os.Unsetenv(k)
		} else {
			os.Setenv(k, v)
		}
	}
	defer func() {
		for k, v := range saved {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()
	fn()
}

// A real Ed25519 public key, base64url unpadded, from the golden vector key.
const testKey = "a1b2c3d4e5f60718=6PLHU7ge_LnZAdyxdSHY_TmGkbTLhZWSaVBjbQ4zXVA"

func goodEnv() map[string]string {
	return map[string]string{
		"RUNOS_AID":                "rjwrn",
		"RUNOS_CID":                "v6b",
		"RUNOS_GATE_PUBLIC_KEYS":   testKey,
		"RUNOS_CONSOLE_ORIGINS":    "https://console.runos.com",
		"RUNOS_DISABLE_SINGLE_USE": "",
	}
}

func TestConfigLoadsWhenEverythingIsPresent(t *testing.T) {
	withEnv(t, goodEnv(), func() {
		c, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if c.aid != "rjwrn" || c.cid != "v6b" || len(c.keys) != 1 || len(c.origins) != 1 {
			t.Fatalf("loaded %+v", c)
		}
	})
}

/**
 * THE ESCAPE HATCH. Rule 1 of the single-use design: if any setting can disable or soft-fail the
 * claim, the gate must refuse to start while it is set. Tested rather than documented, because the
 * whole point is that the option does not exist.
 */
func TestRefusesToStartWithSingleUseDisabled(t *testing.T) {
	for _, value := range []string{"1", "true", "yes", "false", "0", "anything at all"} {
		env := goodEnv()
		env["RUNOS_DISABLE_SINGLE_USE"] = value
		withEnv(t, env, func() {
			_, err := loadConfig()
			if err == nil {
				t.Fatalf("RUNOS_DISABLE_SINGLE_USE=%q was accepted", value)
			}
			// Even "false" and "0" are refused: a variable that exists is a variable someone flips.
			if !strings.Contains(err.Error(), "cannot be turned off") {
				t.Errorf("the refusal must say why: %v", err)
			}
		})
	}
}

func TestEveryRequiredValueIsRequired(t *testing.T) {
	for _, missing := range []string{"RUNOS_AID", "RUNOS_CID", "RUNOS_GATE_PUBLIC_KEYS", "RUNOS_CONSOLE_ORIGINS"} {
		env := goodEnv()
		env[missing] = ""
		withEnv(t, env, func() {
			if _, err := loadConfig(); err == nil {
				t.Errorf("started with %s unset", missing)
			}
		})
	}
}

/**
 * A truncated key in a ConfigMap would otherwise present as every session failing its signature,
 * which reads as a compromise rather than as a typo.
 */
func TestKeysAreCheckedAtStartupRatherThanAtFirstUse(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"not base64url", "a1b2c3d4e5f60718=not base64!"},
		{"padded", "a1b2c3d4e5f60718=6PLHU7ge_LnZAdyxdSHY_TmGkbTLhZWSaVBjbQ4zXVA="},
		{"too short", "a1b2c3d4e5f60718=AAAA"},
		{"no key id", "6PLHU7ge_LnZAdyxdSHY_TmGkbTLhZWSaVBjbQ4zXVA"},
		{"a short key id", "a1b2=6PLHU7ge_LnZAdyxdSHY_TmGkbTLhZWSaVBjbQ4zXVA"},
		{"empty", ","},
	} {
		env := goodEnv()
		env["RUNOS_GATE_PUBLIC_KEYS"] = tc.value
		withEnv(t, env, func() {
			if _, err := loadConfig(); err == nil {
				t.Errorf("%s was accepted: %q", tc.name, tc.value)
			}
		})
	}
}

/** Two keys at once is what makes a rotation not an outage. */
func TestTwoKeysAreAcceptedForARotation(t *testing.T) {
	env := goodEnv()
	env["RUNOS_GATE_PUBLIC_KEYS"] = testKey + ",b1b2c3d4e5f60718=6PLHU7ge_LnZAdyxdSHY_TmGkbTLhZWSaVBjbQ4zXVA"
	withEnv(t, env, func() {
		c, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(c.keys))
		}
	})
}

/**
 * The reaper's window is derived from the pass package rather than repeated, so it cannot drift from
 * what the verifier actually accepts.
 */
func TestMaxPassLifetimeTracksTheVerifier(t *testing.T) {
	if got := maxPassLifetime(); got != 300*time.Second {
		t.Fatalf("the longest pass lifetime is %s; the reaper's invariant is built on this", got)
	}
}

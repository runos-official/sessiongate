// Command sessiongate is the RunOS in-cluster session gate.
//
// It lets a person open an interactive session against their own workload: a VM's serial console or
// screen, an SSH session to a VM, or a workspace terminal. The client connects here DIRECTLY; the
// control plane mints a short-lived signed pass and stays out of the data path entirely.
//
// The gate verifies a pass locally against a mounted public key and never calls the control plane,
// so everything it may do is inside the signed bytes and nowhere else.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/runos-official/sessiongate/internal/gate"
	"github.com/runos-official/sessiongate/internal/pass"
	"github.com/runos-official/sessiongate/internal/replay"
	"github.com/runos-official/sessiongate/version"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("runos-session-gate %s\n", version.Version)
		return
	}

	if err := run(log); err != nil {
		log.Error("the session gate could not start", "error", err)
		// NON-ZERO, always. Every startup check below guards something whose failure mode is silent:
		// a gate that ran without them would serve sessions and look healthy while doing the wrong
		// thing. Crash-looping is loud, and loud is the point.
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	log.Info("session gate starting",
		"version", version.Version, "aid", cfg.aid, "cid", cfg.cid,
		"keys", len(cfg.keys), "origins", cfg.origins, "namespace", cfg.namespace)

	upstream, err := gate.InClusterUpstream()
	if err != nil {
		return err
	}

	// The claim gets its OWN http client with its own limits. Sharing the proxy client means a burst
	// of sessions starves the very call that decides replay.
	claimHTTP := &http.Client{
		Transport: upstream.HTTP.Transport,
		Timeout:   replay.ClaimTimeout,
	}
	claimer := &replay.LeaseClaimer{
		Base:      "https://" + upstream.APIHost,
		Namespace: cfg.namespace,
		Token:     upstream.Token,
		HTTP:      claimHTTP,
		Now:       time.Now,
	}

	// The retention window MUST exceed the longest a pass can live, or reaping would make a spent
	// pass claimable again. NewReaper refuses rather than clamping, and this returns the error, so
	// the pod fails to start instead of running with replay quietly reopened.
	reaper, err := replay.NewReaper(claimer.Base, cfg.namespace, upstream.Token, claimHTTP,
		cfg.leaseRetention, maxPassLifetime())
	if err != nil {
		return err
	}

	memory := replay.NewMemory()
	server := &gate.Server{
		Config: gate.Config{
			AID: cfg.aid, CID: cfg.cid, Keys: cfg.keys,
			AllowedOrigins: cfg.origins, Skew: cfg.skew,
		},
		Upstream:    upstream,
		Memory:      memory,
		Claimer:     claimer,
		Log:         log,
		MaxSessions: cfg.maxSessions,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go sweepMemory(ctx, memory, log)
	go reapLeases(ctx, reaper, log)

	public := &http.Server{
		Addr:    ":8080",
		Handler: server.Handler(),
		// No WriteTimeout: a session is a long-lived stream and a write deadline would cut it. The
		// read header timeout still bounds a client that connects and says nothing.
		ReadHeaderTimeout: 10 * time.Second,
	}
	admin := &http.Server{
		Addr:              ":8081",
		Handler:           gate.AdminHandler(func() bool { return true }, func() int32 { return 0 }),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errs := make(chan error, 2)
	go func() { errs <- listen(public, "public") }()
	go func() { errs <- listen(admin, "admin") }()
	log.Info("listening", "public", ":8080", "admin", ":8081")

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	/*
	 * SIGTERM stops NEW sessions and keeps existing ones. A gate that dropped every live session on
	 * a rolling update would make every deploy an outage for whoever was mid-command.
	 *
	 * AND THEN IT ENDS THEM PROPERLY. The drain has a limit, and when it runs out the process exits.
	 * Without the CloseAll below, that exit drops every survivor by closing the TCP with no close
	 * frame, which is the one ending a client cannot interpret: it looks identical to a dead
	 * cluster, a broken network and a refused pass. 4001 tells a client to mint a new pass and
	 * reconnect, which is a different action from anything else it might do.
	 */
	log.Info("draining: no new sessions, existing ones keep running", "live", server.Live())
	server.Drain()

	// The admin listener goes first: a draining gate must stop reporting itself ready, so nothing
	// new is routed to it while it finishes.
	adminCtx, adminCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = admin.Shutdown(adminCtx)
	adminCancel()

	drainDeadline := time.Now().Add(cfg.drainTimeout)
	for time.Now().Before(drainDeadline) {
		if server.Live() == 0 {
			break
		}
		time.Sleep(time.Second)
	}
	if closed := server.CloseAll(gate.CloseDraining, "the session gate is restarting; reconnect"); closed > 0 {
		log.Info("ended sessions that outlasted the drain", "sessions", closed)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return public.Shutdown(shutdownCtx)
}

func listen(s *http.Server, name string) error {
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s listener: %w", name, err)
	}
	return nil
}

// maxPassLifetime is the longest any kind may live, read from the pass package rather than repeated
// here, so the reaper's invariant cannot drift from what the verifier accepts.
func maxPassLifetime() time.Duration {
	longest := time.Duration(0)
	for _, k := range []pass.Kind{
		pass.KindVMSSH, pass.KindVMSerial, pass.KindVMVNC, pass.KindWSTerminal, pass.KindWSFiles,
	} {
		if d := k.MaxLifetime(); d > longest {
			longest = d
		}
	}
	return longest
}

func sweepMemory(ctx context.Context, m *replay.Memory, log *slog.Logger) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Sweep(time.Now())
		}
	}
}

func reapLeases(ctx context.Context, r *replay.Reaper, log *slog.Logger) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Logged, never fatal: an unhandled failure on a ticker takes the process down, and a
			// missed sweep is retried on the next tick.
			deleted, err := r.ReapOnce(ctx)
			if err != nil {
				log.Warn("lease reap failed", "error", err)
				continue
			}
			if deleted > 0 {
				log.Info("spent pass leases collected", "deleted", deleted)
			}
		}
	}
}

// --- configuration ------------------------------------------------------------------------------

type config struct {
	aid, cid       string
	keys           pass.Keys
	origins        []string
	skew           time.Duration
	namespace      string
	leaseRetention time.Duration
	maxSessions    int32
	// drainTimeout is how long live sessions may keep running after SIGTERM. It must be SHORTER than
	// the pod's terminationGracePeriodSeconds, or the kubelet kills the process before it can tell
	// anyone anything, which puts us back to a frameless drop.
	drainTimeout time.Duration
}

/*
loadConfig reads the environment and refuses anything ambiguous.

EVERY MISSING VALUE IS FATAL. There is no default cluster id, no default key, no "" that means
"allow everything". A gate that started with an empty key set would refuse every session and look
like a networking fault; a gate that started with an empty origin allowlist would either refuse every
browser or, worse, allow every one, depending on which way a later reader wrote the check.
*/
func loadConfig() (config, error) {
	var c config
	var err error

	if c.aid, err = required("RUNOS_AID"); err != nil {
		return c, err
	}
	if c.cid, err = required("RUNOS_CID"); err != nil {
		return c, err
	}
	c.namespace = envOr("RUNOS_NAMESPACE", "runos")

	// THE ESCAPE HATCH CHECK. If anything ever sets this, the gate refuses to start rather than
	// running with single use disabled. Deliberately not documented as an option: the point is that
	// the setting cannot exist, and a startup failure is how that is enforced rather than a comment.
	if v := os.Getenv("RUNOS_DISABLE_SINGLE_USE"); v != "" {
		return c, fmt.Errorf(
			"RUNOS_DISABLE_SINGLE_USE is set to %q. Single use cannot be turned off: a pass that can "+
				"be replayed is not a session credential. Remove the variable", v)
	}

	raw, err := required("RUNOS_GATE_PUBLIC_KEYS")
	if err != nil {
		return c, err
	}
	if c.keys, err = parseKeys(raw); err != nil {
		return c, err
	}

	originsRaw, err := required("RUNOS_CONSOLE_ORIGINS")
	if err != nil {
		return c, err
	}
	for _, o := range strings.Split(originsRaw, ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.origins = append(c.origins, o)
		}
	}
	if len(c.origins) == 0 {
		return c, fmt.Errorf("RUNOS_CONSOLE_ORIGINS is set but names no origin")
	}

	c.skew = durationOr("RUNOS_CLOCK_SKEW_SECONDS", 30*time.Second)
	c.leaseRetention = durationOr("RUNOS_LEASE_RETENTION_SECONDS", time.Hour)
	c.maxSessions = int32(intOr("RUNOS_MAX_SESSIONS", 128))
	// Shorter than the manifest's 300s grace on purpose, so the gate closes its own sessions rather
	// than being killed mid-explanation.
	c.drainTimeout = durationOr("RUNOS_DRAIN_SECONDS", 240*time.Second)
	return c, nil
}

/*
parseKeys reads "kid=base64url,kid=base64url".

TWO KEYS ARE EXPECTED DURING A ROTATION, and holding both is what makes a rotation not an outage.
Every key is checked for length here rather than at first use: a truncated key in a ConfigMap would
otherwise present as every session failing its signature, which reads as a compromise rather than a
typo.
*/
func parseKeys(raw string) (pass.Keys, error) {
	keys := pass.Keys{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		kid, encoded, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("RUNOS_GATE_PUBLIC_KEYS entries look like kid=key, this one is %q", entry)
		}
		kid = strings.TrimSpace(kid)
		if len(kid) != 16 {
			return nil, fmt.Errorf("key id %q is not 16 characters", kid)
		}
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("the key for %s is not unpadded base64url: %w", kid, err)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("the key for %s is %d bytes, an Ed25519 public key is %d",
				kid, len(key), ed25519.PublicKeySize)
		}
		keys[kid] = ed25519.PublicKey(key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("RUNOS_GATE_PUBLIC_KEYS names no usable key")
	}
	return keys, nil
}

func required(name string) (string, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return "", fmt.Errorf("%s is required and unset", name)
	}
	return v, nil
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func durationOr(name string, fallback time.Duration) time.Duration {
	if v := intOr(name, 0); v > 0 {
		return time.Duration(v) * time.Second
	}
	return fallback
}

func intOr(name string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

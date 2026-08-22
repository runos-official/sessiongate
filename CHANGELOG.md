# Changelog

All notable changes to the RunOS Session Gate are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline extracts the section matching the pushed tag (`## vX.Y.Z`)
as the GitHub release notes, so every released version needs a section here.

## v0.1.0-rc.2

**rc.1 could not open a workspace terminal, and this is the fix.** The gate verified the pass, then
dialled the workspace WITHOUT forwarding it, so runostty refused every session with "no session pass
was offered" and the client saw 4401. VM consoles were unaffected, which made it a confusing partial
failure: serial, VNC and SSH all worked while every workspace terminal was refused. Do not install
rc.1.

- **The pass is forwarded to the workspace**, which verifies it again. The workspace is the only
  party that knows whose workspace it is, so it is the only one that can check the pass was minted
  for THIS one. Proven end to end from the browser: k9s rendering on a real cluster through the
  gate.
- **A session now ends with a close frame instead of a dropped socket.** In coder/websocket a read
  whose context is cancelled closes the connection abruptly, with no close frame, so a perfectly
  normal one-shot ended with "failed to read frame header: EOF". Reads now use the request context
  and the peer is closed with a status, so a client can tell a clean ending from a broken one.
- **Surviving sessions are ended with a reason.** A gate that is shutting down closes with 4001
  rather than vanishing, so the CLI and the console can both say "restarting, try again".
- **Six defects from an adversarial review of the shipped code**, including the trailing-newline
  accept in the base64 decoder (Go's base64 ignores \r and \n at every strictness, so the alphabet
  is now checked before the decode), an int64 overflow that defeated the lifetime cap (compared in
  seconds, with boundary vectors), and silent truncation in the Lease reaper past 8 MiB (now
  paginated).
- **The verifier is fuzzed.** `pass.Verify` is the first thing an unauthenticated client reaches, so
  a panic there is a denial of service anyone can trigger. 47 million executions, zero panics, and
  the invariant that it never returns both a payload and an error.
- KubeVirt's real subprotocol behaviour recorded from a live handshake: it advertises nothing and
  ignores an unknown offer rather than failing the handshake. The old claim that it advertises
  `plain.kubevirt.io` was hearsay; virtctl asks for it and KubeVirt echoes it back.

## v0.1.0-rc.1

The gate now runs. Verifies a pass locally, burns it once, dials the far end, and pipes.

- The session pass: Ed25519 over the transmitted bytes, unpadded base64url, no algorithm field and
  no JWT library. 67 golden vectors shared with conductor's verifier; both must agree on every
  verdict and on the decoded payload.
- The port-22 pin. `/portforward/22/tcp` and `/portforward/2222/tcp` authorize identically, because
  kube-apiserver drops the port segment before the access review, so the literal is the only limit
  that exists. Five layers defend it, including a fuzz test that never names the constant.
- Single use by a named Lease create, which is a compare-and-set in etcd. Fails closed on every
  claim fault, never deletes on a failure path, and reaps its own spent leases because Kubernetes
  does not collect them.
- Every pass refusal shares one client message, so the gate is not an oracle for a prober.
- Startup refuses an unsafe configuration rather than running: no keys, no origins, a truncated key,
  a lease retention shorter than a pass can live, or any attempt to disable single use.

## v0.0.0-rc.1

Repository skeleton. No session handling yet.

- Elastic License 2.0, `NOTICE`, and the RunOS public-repo file set.
- CI: gofmt, `go vet`, CGO-off build, `go test -race`, changelog extraction, and
  a linux/amd64 image build.
- Release pipeline: multi-arch image to `ghcr.io/runos-official/sessiongate`,
  keyless Sigstore build-provenance attestation pushed to the registry, and the
  RunOS pre-release rule (a semver pre-release suffix publishes and is pinnable
  but never moves `:latest`).
- Distroless, non-root (uid 65532) image. The binary prints its version and
  exits, which is enough to prove version stamping end to end.

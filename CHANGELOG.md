# Changelog

All notable changes to the RunOS Session Gate are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline extracts the section matching the pushed tag (`## vX.Y.Z`)
as the GitHub release notes, so every released version needs a section here.

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

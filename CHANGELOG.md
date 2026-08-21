# Changelog

All notable changes to the RunOS Session Gate are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release pipeline extracts the section matching the pushed tag (`## vX.Y.Z`)
as the GitHub release notes, so every released version needs a section here.

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

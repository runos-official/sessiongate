# RunOS Session Gate

`runos-session-gate` is a small in-cluster service that lets a person open an
interactive session against their own workload: a virtual machine's serial
console or screen, an SSH session to a virtual machine, or a workspace
terminal. One instance runs per RunOS cluster.

> **Status: implemented and running.** The gate verifies a session pass locally,
> burns it once, dials the far end and pipes bytes, for all four session kinds.
> It is deployed on RunOS dev and has been proven on hardware: SSH into a
> virtual machine, its serial console, a VNC framebuffer over 1 MiB, and a
> workspace terminal from both the CLI and the browser.

## Why it exists

Without it, the RunOS control plane has to reach into a cluster from outside to
proxy an interactive session, which requires the cluster's Kubernetes API to be
reachable from the internet and requires the control plane to hold cluster
credentials for the life of every session. Neither is acceptable.

The gate inverts that. It runs inside the cluster, is published on 443 like any
other web workload, and the client connects to it directly. The control plane
issues a short-lived, signed pass and stays out of the data path.

## Design rules

These are the properties the implementation has to keep. They are listed here
because they are easy to erode by accident.

- **The caller never names the target.** The gate reads the target and the kind
  of session out of the signed pass, and from nowhere else. A client cannot ask
  for a machine or a port it was not issued a pass for.
- **The gate holds no long-lived credential.** It verifies an Ed25519 signature
  with a public key mounted at startup. It holds no private key, and it never
  calls the control plane to check a pass.
- **Passes are short-lived and single-use.** The gate independently caps the
  lifetime it will honour, rather than trusting the pass's own expiry alone.
- **Narrow permissions.** The gate's Kubernetes access is limited to the
  subresources an interactive session needs. It is not a general path to the
  Kubernetes API.
- **The tenant boundary is the account.** A pass is only ever issued for a
  workload in the caller's own account.

## Build

```sh
make build      # local binary, stamped with the version
make test       # go test -race ./...
make vet        # go vet ./...
make image      # multiarch image, local, no push
```

Before opening a pull request, run the same gates CI runs:

```sh
gofmt -l .        # must print nothing
go vet ./...
go build ./...
go test -race ./...
```

## Releases

Work lands on `dev`. A release is cut from `dev` by `scripts/release.sh`, which
runs every gate (the leak gate of a public repo, gofmt, build, vet and the race
tests, and a green CI run on the exact commit), tags the commit, and waits for
the release workflow that the tag starts:

```sh
make release RELEASE_VERSION=v0.2.0-rc.1 CHECK=1   # every gate, no tag, no push
make release RELEASE_VERSION=v0.2.0-rc.1           # gates, tag, push, watch, verify
```

The release workflow (`.github/workflows/release.yml`) builds the image and
publishes it. Anyone can read its run in GitHub Actions. The maintainers' release
tooling cuts the same tags through the same script and shows the same run.

A tag with a semver pre-release suffix (for example `v0.2.0-rc.1`) is published
and pinnable by its exact version, and is flagged a GitHub pre-release, but
never moves the `:latest` tag. A final release is cut from the exact commit that
shipped as a release candidate. `deployed` records the last commit that shipped.

Every released image carries a keyless Sigstore build-provenance attestation.
Verify one with:

```sh
gh attestation verify oci://ghcr.io/runos-official/sessiongate:<version> \
  --repo runos-official/sessiongate
```

## Security

Report vulnerabilities to **security@runos.com**. See [SECURITY.md](SECURITY.md).

## Licence

[Elastic License 2.0](LICENSE). Source-available, not open source: the source is
published for transparency and security review, and use is subject to the terms
in `LICENSE`. See [NOTICE](NOTICE).

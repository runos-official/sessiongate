# RunOS Session Gate

`runos-session-gate` is a small in-cluster service that lets a person open an
interactive session against their own workload: a virtual machine's serial
console or screen, an SSH session to a virtual machine, or a workspace
terminal. One instance runs per RunOS cluster.

> **Status: skeleton.** This version builds, stamps its version and exits. No
> session handling exists yet. It is published to prove the release pipeline
> and the image before the implementation lands.

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

A release is cut by pushing a tag:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

A tag with a semver pre-release suffix (for example `v0.1.0-rc.1`) is published
and pinnable by its exact version, and is flagged a GitHub pre-release, but
never moves the `:latest` tag.

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

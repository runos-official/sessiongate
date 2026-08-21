# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in any RunOS product or service,
including the session gate, API, web console, or infrastructure, please report
it responsibly.

**Email:** security@runos.com

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact

We will acknowledge reports within 8 hours and aim to provide a fix or
mitigation plan within 3 days for critical issues.

## Security Practices

> **This version is a skeleton.** It builds, prints its version and exits. The
> practices below are the rules the implementation must keep, published here
> first so that a later change that erodes one is visible as a change of policy
> rather than an unremarked detail.

- **No hardcoded secrets.** The repository contains no credentials, tokens, or
  private keys, and none are baked into the image. The gate reads what it needs
  at runtime from a mounted ConfigMap and its service-account token.
- **No signing key in the cluster.** The gate verifies an Ed25519 signature
  using a public key only. The private half never leaves the RunOS control
  plane, so a compromised gate cannot mint a session for anything.
- **No callback on the hot path.** Verification is local. The gate does not
  call the control plane to check a pass, so it cannot be turned into an
  oracle, and a slow control plane cannot stall a session.
- **The caller never names the target.** The machine, the port and the kind of
  session are read from the signed pass and from nowhere else. A request body
  or query string cannot redirect a session, which is what keeps the gate from
  becoming a general tunnel into a private network.
- **Independent expiry cap.** The gate enforces its own maximum pass age rather
  than trusting the value inside the pass, so a control-plane bug that mints a
  long-lived pass cannot produce a long-lived credential.
- **Single use.** A pass is redeemable once. Replay is refused.
- **Narrow Kubernetes permissions.** The gate's role covers the specific
  subresources an interactive session needs, not general cluster access.
- **Non-root, distroless, read-only root filesystem.** The image carries no
  shell and no package manager, runs as uid 65532, and the deployment pairs it
  with a read-only root filesystem. The gate shells out to nothing.
- **The tenant boundary is the account.** A pass is only ever issued for a
  workload in the caller's own account. The gate enforces the boundary the pass
  states; the control plane is what decides it.

## Release Integrity & Trust Model

The container image a cluster runs is cryptographically tied to the artifact
this repository's release pipeline produced.

1. **Keyless build-provenance attestation.** The release workflow
   (`.github/workflows/release.yml`) runs `actions/attest-build-provenance`,
   which issues a keyless Sigstore attestation for every released image. The
   attestation binds the image digest to this workflow's OIDC identity. No
   long-lived signing secret is stored, which is safe for a public repo. Verify
   a released image with:

   ```sh
   gh attestation verify oci://ghcr.io/runos-official/sessiongate:<v> \
     --repo runos-official/sessiongate
   ```

2. **Stable vs. release-candidate tags.** Only a stable (non-prerelease) build
   moves the `:latest` tag. A pre-release tag with a semver suffix
   (for example `v0.1.0-rc.1`) is published and pinnable by its exact version
   and flagged a GitHub prerelease, but never tagged `:latest`, so normal
   consumers are not silently moved onto a candidate build.

3. **Base images pinned by digest.** Both the build stage and the runtime stage
   pin their base image by sha256 digest as well as by tag, so a re-tag
   upstream cannot silently change what is built or shipped.

### What attestation does NOT guarantee (accepted limitation)

Attestation proves an artifact *came from this workflow*. It does **not** prove
the artifact is benign. A compromised build, malicious code merged into the
release branch, or a subverted workflow/runner would produce an
evil-but-validly-attested image that passes verification. The attestation is
blind to this class of attack.

The only defense against a subverted build is repo-side access control: keeping
malicious code and workflow edits out in the first place. The two layers below
are that defense.

### Codified in-repo: pinned action SHAs

Every `uses:` in both workflows is pinned to a full 40-character commit SHA
with a trailing version comment (for example
`actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32 # v4.1.0`).
A moved tag on a third-party action therefore cannot silently swap in new code.
**Re-confirm this on every workflow edit**, and pin any newly added action the
same way before merging.

### Admin-only hardening checklist (human/admin action required)

These controls cannot be enforced by files in this repo. A GitHub org/repo
admin must apply them in repository settings; they are the actual mitigation for
the build-compromise limitation above:

- [ ] **Branch protection** on the release branch: require pull requests, block
  direct pushes and force-pushes.
- [ ] **Required PR review**: at least one approving review before merge.
- [ ] **Restrict workflow edits**: limit who can modify files under
  `.github/workflows/` and tighten the repo's Actions permissions.
- [ ] **Restrict tag push and release publishing**: the release workflow
  triggers on `v*` tag pushes, so control over who can push tags and publish
  releases is control over what gets attested and shipped into every cluster
  that runs this image.

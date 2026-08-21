# Contributing

Thanks for contributing to the RunOS session gate.

## Prerequisites

- **Go 1.25+** (see `go.mod`). The gate is CGO-free; `make build` sets
  `CGO_ENABLED=0` for you.
- **Docker Buildx** if you build the container image locally.

## Build and test

```sh
make build       # build a local binary stamped with the version
make test        # go test -race ./...
make vet         # go vet ./...
make image       # build the multiarch image locally (no push)
```

Before opening a PR, run the same gates CI runs:

```sh
gofmt -l .        # must print nothing
go vet ./...
go build ./...
go test -race ./...
```

## Code conventions

- **CGO stays off.** The release image is distroless and the binary must stay
  static. A dependency that needs cgo breaks the cross-compiled build, and CI
  fails on it deliberately.
- **No shelling out.** The gate carries no shell in its image. Anything that
  needs a subprocess belongs somewhere else.
- **Pin every GitHub Action by full commit SHA** with a trailing version
  comment. CI and the release pipeline are part of the security boundary; see
  `SECURITY.md`.
- **Every released version needs a `## vX.Y.Z` section in `CHANGELOG.md`.** CI
  fails if a section extracts empty, because the release pipeline uses it as the
  release notes.

## Releases

Releases are cut by pushing a tag:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

A semver pre-release suffix (`v0.1.0-rc.1`) publishes and is pinnable by exact
version, is flagged a GitHub pre-release, and never moves `:latest`.

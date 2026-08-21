# Base images are pinned by digest in addition to the tag so a re-tag upstream
# can't silently change what we build/ship. To refresh after a deliberate base
# bump, resolve the new multi-arch index digest with:
#   docker buildx imagetools inspect golang:1.25-alpine3.21          # copy the Digest
#   docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot
# The build stage runs natively on the BUILD platform (no QEMU) and
# cross-compiles to the TARGET platform with Go's own toolchain. The gate is
# CGO-free, so no C toolchain is needed and the binary is already static.
# Go base tracks the go.mod toolchain floor (go 1.25.x).
FROM --platform=$BUILDPLATFORM golang:1.25-alpine3.21@sha256:b4dbd292a0852331c89dfd64e84d16811f3e3aae4c73c13d026c4d200715aff6 AS build_deps

WORKDIR /workspace

COPY go.mod .

RUN go mod download

FROM build_deps AS build

COPY . .

ARG TARGETOS TARGETARCH
# VERSION is injected by the release pipeline (the pushed git tag) and stamped
# into version.Version via -ldflags -X. Defaults to "dev" for plain builds.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o sessiongate \
    -trimpath \
    -ldflags "-w -X github.com/runos-official/sessiongate/version.Version=${VERSION}" .

# Distroless and non-root, DELIBERATELY DIFFERENT from the cluster agent, which
# ships alpine and runs as root. That difference is not an oversight: the agent
# shells out to kubectl, helm and buildctl, so it needs a shell, a package set
# and root. The gate shells out to nothing and talks only to the Kubernetes API
# and one in-cluster HTTP endpoint, so it has no reason to carry any of that.
# uid 65532 is distroless's `nonroot`. The deployment manifest pairs this with a
# read-only root filesystem; keep the two together.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a

COPY --from=build /workspace/sessiongate /usr/local/bin/sessiongate

USER 65532:65532

ENTRYPOINT ["sessiongate"]

# Makefile for the RunOS Session Gate

GREEN := \033[0;32m
RED   := \033[0;31m
BLUE  := \033[0;34m
CYAN  := \033[0;36m
GRAY  := \033[0;90m
NC    := \033[0m

GO ?= $(shell which go)

# Version is the latest git tag (sans leading v), falling back to "dev". The
# release pipeline tags the commit, so this matches the published image tag.
#
# Two assignments on purpose. The obvious one-liner,
#   $(shell git describe ... | sed 's/^v//' || echo "dev")
# never falls back: `||` sees the exit status of the LAST command in the pipe,
# which is sed's, and sed succeeds on empty input. On a repo with no tags (a
# fresh clone, or a shallow CI checkout without tags) that stamps an EMPTY
# version rather than "dev". clusteragent, nodeagent and cli all carry that
# form and hide it only because they have tags.
VERSION  := $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
VERSION  := $(if $(VERSION),$(VERSION),dev)
LDFLAGS  := -X github.com/runos-official/sessiongate/version.Version=$(VERSION)

# Container image. The release pipeline publishes the multiarch image here.
IMAGE_NAME := ghcr.io/runos-official/sessiongate
IMAGE_TAG  := $(VERSION)

.DEFAULT_GOAL := help

# ============================================================================
# Development
# ============================================================================

# CGO is off: the gate has no C dependency and the binary must stay static so
# it cross-compiles cleanly into a distroless image.
.PHONY: build
build:
	@CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o sessiongate .

.PHONY: test
test:
	@echo "$(GRAY)[`date '+%H:%M:%S'`]$(NC) $(BLUE)Running tests...$(NC)"
	@$(GO) test -race ./...
	@echo "$(GRAY)[`date '+%H:%M:%S'`]$(NC) $(GREEN)Tests passed$(NC)"

.PHONY: vet
vet:
	@$(GO) vet ./...

.PHONY: clean
clean:
	@rm -f sessiongate

.PHONY: version
version:
	@echo "$(VERSION)"

# Ask THIS verifier whether it accepts passes minted by conductor's real code.
#
# The golden vectors hold both implementations to the same verdicts on a frozen set of inputs. This
# is the other direction, and it catches a different failure: conductor emitting something no gate
# will take, from code paths the vectors never exercise (its own JSON serialiser, its own field
# order, its own key handling). Needs the conductor repo beside this one.
.PHONY: crosscheck
crosscheck:
	@cd ../conductor && npx tsx scripts/mint-for-gate-crosscheck.ts | (cd ../sessiongate && $(GO) run ./internal/pass/crosscheck)

# ============================================================================
# Container image (local). CI publishes via .github/workflows/release.yml.
# ============================================================================

# Build the multiarch image locally without pushing.
.PHONY: image
image:
	@docker buildx create --name multiarch-builder --use >/dev/null 2>&1 || docker buildx use multiarch-builder
	@docker buildx inspect --bootstrap >/dev/null
	@docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-t "$(IMAGE_NAME):$(IMAGE_TAG)" .

# ============================================================================
# Help
# ============================================================================

.PHONY: help
help:
	@echo "$(CYAN)RunOS Session Gate$(NC)"
	@echo ""
	@echo "  make build      Build a local binary stamped with the version"
	@echo "  make test       Run tests with the race detector"
	@echo "  make vet        Run go vet"
	@echo "  make version    Show the current version"
	@echo "  make clean      Remove build artifacts"
	@echo ""
	@echo "  make image      Build the multiarch image locally (no push)"
	@echo "  make crosscheck Verify passes minted by conductor (needs ../conductor)"
	@echo ""
	@echo "  Releases are cut by pushing a tag: git tag vX.Y.Z && git push origin vX.Y.Z"

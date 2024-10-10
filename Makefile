
BIN_NAME := attestation-cli
MODULE := github.com/mbreban/attestation

GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_DIRTY := $(shell test -n "`git status --porcelain`" && echo "+CHANGES" || true)
BUILD_DATE := $(shell date '+%Y-%m-%d-%H:%M:%S')

LDFLAGS := -X '$(MODULE)/cmd/attestation-cli/version.GitCommit=$(GIT_COMMIT)$(GIT_DIRTY)' \
	-X '$(MODULE)/cmd/attestation-cli/version.BuildDate=$(BUILD_DATE)'

.PHONY: default
default: help

.PHONY: help
help:
	@echo 'Management commands for attestation:'
	@echo
	@echo 'Usage:'
	@echo '    make build           Compile attestation-cli binary.'
	@echo '    make install         Install attestation-cli binary.'
	@echo '    make tidy            Tidy up modules.'
	@echo '    make update          Update dependencies.'
	@echo '    make test            Run tests.'
	@echo '    make test-samples    Run sample tests.'
	@echo '    make clean           Clean the directory tree.'
	@echo

.PHONY: build
build:
	@echo "building $(BIN_NAME)"
	@echo "GOPATH=$(GOPATH)"
	go build -ldflags "$(LDFLAGS)" -o bin/$(BIN_NAME) ./cmd/attestation-cli

.PHONY: install
install:
	go install ./cmd/attestation-cli

.PHONY: tidy
tidy:
	go mod tidy
	go mod verify

.PHONY: update
update:
	go get -u ./...

.PHONY: test
test:
	go test ./ -cover

.PHONY: test-samples
test-samples:
	go test ./ -tags=samples

.PHONY: clean
clean:
	@test ! -e bin/$(BIN_NAME) || rm bin/$(BIN_NAME)

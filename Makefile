
.PHONY: default
default: help

.PHONY: help
help:
	@echo 'Management commands for attestation:'
	@echo
	@echo 'Usage:'
	@echo '    make install         Install attestation-cli binary.'
	@echo '    make tidy            Tidy up modules.'
	@echo '    make update          Update dependencies.'
	@echo '    make test            Run tests.'
	@echo

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

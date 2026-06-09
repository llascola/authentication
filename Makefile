.PHONY: build test vet fmt fmt-check lint check ci

CMDS := $(wildcard cmd/*)
GOFILES := $(shell find . -name '*.go' -not -path './bin/*')

build:
	$(foreach cmd,$(CMDS),go build -o bin/$(notdir $(cmd)) ./$(cmd);)

test:
	go test -race ./...

vet:
	go vet ./...

# Write formatting changes in place.
fmt:
	gofmt -w $(GOFILES)

# Fail if any file is not gofmt-clean (used by CI). Prints offending files.
fmt-check:
	@out="$$(gofmt -l $(GOFILES))"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	go tool staticcheck ./...

# Everything CI runs, in one local command.
check ci: fmt-check vet lint test

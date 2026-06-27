.PHONY: build test vet fmt fmt-check lint vuln check ci

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

# Scan dependencies + stdlib for known vulnerabilities. govulncheck is
# call-graph aware: it reports only vulns this code can actually reach, so a
# finding here is real and actionable. Kept OUT of `check`/CI's blocking gate
# on purpose: the vuln DB is live, so a newly-published advisory could fail an
# unchanged tree. It runs as its own scheduled job (.github/workflows/vuln.yml)
# instead. Run locally any time with `make vuln`.
vuln:
	go tool govulncheck ./...

# Everything the blocking CI gate runs, in one local command.
check ci: fmt-check vet lint test

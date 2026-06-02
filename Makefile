.PHONY: build test

CMDS := $(wildcard cmd/*)

build:
	$(foreach cmd,$(CMDS),go build -o bin/$(notdir $(cmd)) ./$(cmd);)

test:
	go test ./...

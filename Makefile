# AegisBastion Connector Hub — root Makefile.
# Windows-first (Git Bash): all tooling is vendored inside the repo (bin/, node_modules/).
# Override tool paths if you have system installs:  make BUF=buf GO=go

GO        ?= go
NODE      ?= node
NPM       ?= npm.cmd
BUF       ?= $(CURDIR)/bin/buf.exe

# buf finds protoc-gen-go / protoc-gen-go-grpc on PATH; bin/ holds the vendored copies.
export PATH := $(CURDIR)/bin:$(PATH)

BUF_VERSION       := 1.72.0
PROTOC_GEN_GO     := v1.36.6
PROTOC_GEN_GO_GRPC := v1.5.1

.PHONY: tools proto-lint proto-gen schemas-validate build-gen verify clean-gen

## tools: install codegen plugins into ./bin and npm dev deps into ./node_modules
tools:
	GOBIN=$(CURDIR)/bin $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO)
	GOBIN=$(CURDIR)/bin $(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC)
	$(NPM) install

## proto-lint: lint the buf module (STANDARD rules)
proto-lint:
	$(BUF) lint proto

## proto-gen: regenerate Go + TS stubs into gen/ (lint first)
proto-gen: proto-lint
	$(BUF) generate proto --template proto/buf.gen.yaml

## schemas-validate: validate JSON Schemas and their example instances (ajv, draft 2020-12)
schemas-validate:
	$(NODE) scripts/validate-schemas.mjs

## build-gen: compile the generated Go stubs
build-gen:
	cd gen/go && $(GO) build ./...
	$(NODE) node_modules/typescript/bin/tsc --noEmit -p gen/ts/tsconfig.json

## verify: full contract verification (generate, compile Go + TS, validate schemas)
verify: proto-gen schemas-validate build-gen

## clean-gen: remove generated stubs (keeps go.mod / package.json)
clean-gen:
	rm -rf gen/go/aegisbastion gen/ts/aegisbastion

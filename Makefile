BINARY_NAME := rxds
MAIN_PATH := ./cmd/rxds
BUILD_DIR := ./dist
COVERAGE_FILE := coverage.out

GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOVET := $(GOCMD) vet

LDFLAGS := -s -w
BUILD_FLAGS := -trimpath -ldflags "$(LDFLAGS)"

GOLANGCI_LINT := $(shell which golangci-lint 2> /dev/null)

.PHONY: all build clean test test-coverage lint-install lint lint-fix security fmt vet tidy check ci help

all: lint test build

build:
	@echo "building $(BINARY_NAME)..."
	@CGO_ENABLED=0 $(GOBUILD) $(BUILD_FLAGS) -o $(BINARY_NAME) $(MAIN_PATH)

clean:
	@$(GOCLEAN)
	@rm -f $(BINARY_NAME)
	@rm -rf $(BUILD_DIR)
	@rm -f $(COVERAGE_FILE)

test:
	@$(GOTEST) -v -race -cover ./...

test-coverage:
	@$(GOTEST) -v -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o coverage.html

lint-install:
ifndef GOLANGCI_LINT
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin
endif

lint: lint-install
	@golangci-lint run --timeout=5m ./...

lint-fix: lint-install
	@golangci-lint run --fix --timeout=5m ./...

security: lint-install
	@golangci-lint run --disable-all --enable=gosec,bodyclose --timeout=5m ./...

fmt:
	@$(GOFMT) -s -w .
	@$(GOCMD) fmt ./...

vet:
	@$(GOVET) ./...

tidy:
	@$(GOMOD) tidy
	@$(GOMOD) verify

check: fmt vet lint

ci: tidy fmt vet lint test

help:
	@echo "targets:"
	@echo "  build          build the binary"
	@echo "  test           run tests"
	@echo "  test-coverage  run tests with coverage"
	@echo "  lint           run linters"
	@echo "  lint-fix       run linters with auto-fix"
	@echo "  security       run security linters"
	@echo "  fmt            format code"
	@echo "  vet            run go vet"
	@echo "  tidy           tidy modules"
	@echo "  check          fmt + vet + lint"
	@echo "  ci             full ci check"
	@echo "  clean          clean artifacts"

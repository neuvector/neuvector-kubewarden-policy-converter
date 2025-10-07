# Project settings
APP_NAME := nvrules2kw
CMD_DIR := ./cmd/$(APP_NAME)
BIN_DIR := ./bin

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GO111MODULE=on go build -o $(BIN_DIR)/$(APP_NAME) $(CMD_DIR)
	@echo "Built binary at $(BIN_DIR)/$(APP_NAME)"

# Run the app
.PHONY: run
run: build
	@echo "Running $(APP_NAME)..."
	@$(BIN_DIR)/$(APP_NAME)

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@go test -v -race $$(go list ./... | grep -v /e2e)  -coverprofile coverage/unit-test/cover.out -covermode=atomic

# Clean built files
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Tidy go.mod
.PHONY: tidy
tidy:
	go mod tidy

.PHOHY: lint
lint: golangci-lint
	$(GOLANGCI_LINT) run --verbose

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: e2e-test
e2e-test: kwctl build
	@echo "Running e2e tests..."
	@PATH="$(PWD)/bin:$(PATH)" go test -v -race ./test/e2e/... -coverprofile coverage/e2e-test/cover.out -covermode=atomic -timeout 60m

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION)
KWCTL := $(LOCALBIN)/kwctl

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.3.0
KWCTL_VERSION := v1.29.1

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,${GOLANGCI_LINT_VERSION})

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary (ideally with version)
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f $(1) ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv "$$(echo "$(1)" | sed "s/-$(3)$$//")" $(1) ;\
}
endef

.PHONY: kwctl
kwctl: $(KWCTL) ## Download kwctl locally if necessary
$(KWCTL): $(LOCALBIN)
	@[ -f $(KWCTL) ] || { \
		echo "Installing kwctl..."; \
		mkdir -p $(LOCALBIN); \
		curl -sSLf https://github.com/kubewarden/kwctl/releases/download/$(KWCTL_VERSION)/kwctl-linux-x86_64.zip -o $(KWCTL).zip; \
		unzip -o $(KWCTL).zip -d $(LOCALBIN)/; \
		rm $(KWCTL).zip; \
		mv $(LOCALBIN)/kwctl-linux-x86_64 $(KWCTL); \
		chmod +x $(KWCTL); \
	}

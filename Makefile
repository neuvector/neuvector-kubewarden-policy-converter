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
	GO111MODULE=on go build -o $(BIN_DIR)/$(APP_NAME) $(CMD_DIR)
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
	@go test -v -race ./...

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

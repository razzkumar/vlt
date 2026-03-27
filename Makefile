# Makefile for vlt

BINARY_NAME=vlt
BINARY_PATH=./$(BINARY_NAME)
MAIN_PATH=./cmd/cli
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: all build clean install uninstall test test-coverage test-race test-integration fmt vet help

all: build

# Build the binary
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) $(MAIN_PATH)

# Clean build artifacts
clean:
	go clean
	rm -f $(BINARY_NAME)

# Install to system PATH
install: build
	sudo mv $(BINARY_NAME) /usr/local/bin/

# Uninstall from system PATH
uninstall:
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

# Format Go code
fmt:
	go fmt ./...

# Run Go vet
vet:
	go vet ./...

# Run tests
test:
	go test ./...

# Run tests with coverage report
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run tests with race detector
test-race:
	go test -race ./...

# Run integration tests (requires Docker)
test-integration:  ## Run integration tests (requires Docker)
	go test -tags=integration -count=1 -timeout 120s ./...

# Download dependencies
deps:
	go mod download
	go mod tidy

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 $(MAIN_PATH)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 $(MAIN_PATH)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 $(MAIN_PATH)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe $(MAIN_PATH)

# Install shell completions
completion-bash: build
	./$(BINARY_NAME) completion bash > /tmp/vlt-bash-completion
	@echo "Bash completion generated at /tmp/vlt-bash-completion"
	@echo "Install with: sudo cp /tmp/vlt-bash-completion /etc/bash_completion.d/vlt"

completion-zsh: build
	./$(BINARY_NAME) completion zsh > /tmp/_vlt-zsh-completion
	@echo "Zsh completion generated at /tmp/_vlt-zsh-completion"
	@echo "Install with: sudo cp /tmp/_vlt-zsh-completion /usr/local/share/zsh/site-functions/_vlt"

completion-fish: build
	./$(BINARY_NAME) completion fish > /tmp/vlt.fish
	@echo "Fish completion generated at /tmp/vlt.fish"
	@echo "Install with: cp /tmp/vlt.fish ~/.config/fish/completions/"

completion-powershell: build
	./$(BINARY_NAME) completion powershell > /tmp/vlt-completion.ps1
	@echo "PowerShell completion generated at /tmp/vlt-completion.ps1"
	@echo "Install by sourcing in your PowerShell profile"

# Install completion for current user's fish shell (if fish is available)
install-completion: build
	@if command -v fish > /dev/null 2>&1; then \
		mkdir -p ~/.config/fish/completions; \
		./$(BINARY_NAME) completion fish > ~/.config/fish/completions/vlt.fish; \
		echo "Fish completion installed to ~/.config/fish/completions/vlt.fish"; \
	else \
		echo "Fish shell not found. Use 'make completion-[bash|zsh|fish|powershell]' to generate completions."; \
	fi

# Show help
help:
	@echo "Available targets:"
	@echo "  build                - Build the binary"
	@echo "  clean                - Clean build artifacts"
	@echo "  install              - Install to /usr/local/bin"
	@echo "  uninstall            - Remove from /usr/local/bin"
	@echo "  fmt                  - Format Go code"
	@echo "  vet                  - Run go vet"
	@echo "  test                 - Run tests"
	@echo "  test-coverage        - Run tests with coverage report"
	@echo "  test-race            - Run tests with race detector"
	@echo "  deps                 - Download and tidy dependencies"
	@echo "  build-all            - Build for multiple platforms"
	@echo "  completion-bash      - Generate bash completion"
	@echo "  completion-zsh       - Generate zsh completion"
	@echo "  completion-fish      - Generate fish completion"
	@echo "  completion-powershell - Generate PowerShell completion"
	@echo "  install-completion   - Install completion for current shell"
	@echo "  help                 - Show this help message"

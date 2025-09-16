# File Crypto - Go Implementation Makefile

.DEFAULT_GOAL := help
BINARY_NAME_ENCRYPT := encrypt
BINARY_NAME_DECRYPT := decrypt
BINARY_NAME_GENKEY := genkey
BINARY_NAME_BUILDER := builder
BUILD_DIR := build
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

## Build Commands

.PHONY: build
build: build-encrypt build-decrypt ## Build both encrypt and decrypt binaries

.PHONY: build-encrypt
build-encrypt: ## Build encrypt binary
	@echo "🔨 Building encrypt binary..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT) ./cmd/encrypt

.PHONY: build-ransom-sim
build-ransom-sim: ## Build ransomware simulation encryptor with embedded key/policy artifacts
	@echo "🎯 Building ransomware simulation package..."
	@mkdir -p $(BUILD_DIR)/sim
	go build $(LDFLAGS) -o $(BUILD_DIR)/sim/decrypt-sim ./cmd/decrypt
	go run ./cmd/genkey -name ransom-sim -out $(BUILD_DIR)/sim >/dev/null
	@PUBKEY_B64=$$(tr -d '\n\r' < $(BUILD_DIR)/sim/public-ransom-sim); \
		PRIVKEY_B64=$$(base64 < $(BUILD_DIR)/sim/private-ransom-sim | tr -d '\n\r'); \
		DECRYPTOR_B64=$$(base64 < $(BUILD_DIR)/sim/decrypt-sim | tr -d '\n\r'); \
		POLICY_B64=$$(base64 < policies/ransomware-sim.yaml | tr -d '\n\r'); \
		go build -ldflags "-X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$${PUBKEY_B64} -X file-crypto/internal/crypto.EmbeddedPrivateKeyBase64=$${PRIVKEY_B64} -X file-crypto/internal/sim.EmbeddedDecryptorBase64=$${DECRYPTOR_B64} -X file-crypto/pkg/policy.EmbeddedPolicyYAML=$${POLICY_B64} -X file-crypto/pkg/config.DefaultSimulationModeStr=true -X file-crypto/pkg/config.DefaultPolicyPathStr=embedded -X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/encrypt-sim ./cmd/encrypt
	@cp $(BUILD_DIR)/sim/private-ransom-sim $(BUILD_DIR)/private-ransom-sim.pem
	@cp $(BUILD_DIR)/sim/decrypt-sim $(BUILD_DIR)/decrypt-sim
	@echo "✅ Simulation encryptor ready: $(BUILD_DIR)/encrypt-sim"
	@echo "   🔑 Private key saved to: $(BUILD_DIR)/private-ransom-sim.pem"
	@echo "   🔓 Decryptor binary: $(BUILD_DIR)/decrypt-sim"
	@echo "   📄 Embedded policy: policies/ransomware-sim.yaml"

.PHONY: build-encrypt-pub
build-encrypt-pub: ## Build encrypt binary embedding RSA public key (PUBKEY_B64 required)
	@if [ -z "$(PUBKEY_B64)" ]; then echo "Error: PUBKEY_B64 not set (base64 DER of RSA public key)"; exit 1; fi
	@echo "🔨 Building encrypt binary (embedded public key)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "-X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$(PUBKEY_B64) -X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT) ./cmd/encrypt

.PHONY: build-decrypt
build-decrypt: ## Build decrypt binary
	@echo "🔨 Building decrypt binary..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT) ./cmd/decrypt

.PHONY: build-genkey
build-genkey: ## Build genkey binary
	@echo "🔨 Building genkey binary..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY) ./cmd/genkey

.PHONY: build-builder
build-builder: ## Build interactive builder CLI
	@echo "🔨 Building builder binary..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_BUILDER) ./cmd/builder

.PHONY: build-linux
build-linux: ## Build binaries for Linux (amd64)
	@echo "🔨 Building for Linux amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-linux-amd64 ./cmd/encrypt
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-linux-amd64 ./cmd/decrypt
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-linux-amd64 ./cmd/genkey

.PHONY: build-linux-pub
build-linux-pub: ## Build Linux encrypt binary with embedded public key (PUBKEY_B64 required)
	@if [ -z "$(PUBKEY_B64)" ]; then echo "Error: PUBKEY_B64 not set (base64 DER of RSA public key)"; exit 1; fi
	@echo "🔨 Building Linux encrypt binary (embedded public key)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "-X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$(PUBKEY_B64) -X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-linux-amd64 ./cmd/encrypt

.PHONY: build-windows
build-windows: ## Build binaries for Windows (amd64)
	@echo "🔨 Building for Windows amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-windows-amd64.exe ./cmd/encrypt
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-windows-amd64.exe ./cmd/decrypt
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-windows-amd64.exe ./cmd/genkey

.PHONY: build-windows-pub
build-windows-pub: ## Build Windows encrypt binary with embedded public key (PUBKEY_B64 required)
	@if [ -z "$(PUBKEY_B64)" ]; then echo "Error: PUBKEY_B64 not set (base64 DER of RSA public key)"; exit 1; fi
	@echo "🔨 Building Windows encrypt binary (embedded public key)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags "-X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$(PUBKEY_B64) -X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-windows-amd64.exe ./cmd/encrypt

.PHONY: build-all
build-all: ## Build binaries for all platforms
	@echo "🔨 Building for all platforms..."
	@mkdir -p $(BUILD_DIR)

	# Windows
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-windows-amd64.exe ./cmd/encrypt
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-windows-amd64.exe ./cmd/decrypt
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-windows-amd64.exe ./cmd/genkey

	# Linux
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-linux-amd64 ./cmd/encrypt
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-linux-amd64 ./cmd/decrypt
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-linux-amd64 ./cmd/genkey
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-linux-arm64 ./cmd/encrypt
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-linux-arm64 ./cmd/decrypt
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-linux-arm64 ./cmd/genkey

	# macOS
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-darwin-amd64 ./cmd/encrypt
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-darwin-amd64 ./cmd/decrypt
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-darwin-amd64 ./cmd/genkey
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-darwin-arm64 ./cmd/encrypt
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-darwin-arm64 ./cmd/decrypt
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-darwin-arm64 ./cmd/genkey
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_BUILDER)-darwin-arm64 ./cmd/builder

.PHONY: build-all-pub
build-all-pub: ## Build encrypt binaries for all platforms with embedded public key (PUBKEY_B64 required)
	@if [ -z "$(PUBKEY_B64)" ]; then echo "Error: PUBKEY_B64 not set (base64 DER of RSA public key)"; exit 1; fi
	@echo "🔨 Building encrypt binaries for all platforms (embedded public key)..."
	@mkdir -p $(BUILD_DIR)

	# Windows (with embedded key)
	GOOS=windows GOARCH=amd64 go build -ldflags "-X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$(PUBKEY_B64) -X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-windows-amd64.exe ./cmd/encrypt
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-windows-amd64.exe ./cmd/decrypt
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-windows-amd64.exe ./cmd/genkey

	# Linux (with embedded key)
	GOOS=linux GOARCH=amd64 go build -ldflags "-X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$(PUBKEY_B64) -X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-linux-amd64 ./cmd/encrypt
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-linux-amd64 ./cmd/decrypt
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-linux-amd64 ./cmd/genkey
	GOOS=linux GOARCH=arm64 go build -ldflags "-X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$(PUBKEY_B64) -X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-linux-arm64 ./cmd/encrypt
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-linux-arm64 ./cmd/decrypt
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-linux-arm64 ./cmd/genkey

	# macOS (with embedded key)
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$(PUBKEY_B64) -X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-darwin-amd64 ./cmd/encrypt
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-darwin-amd64 ./cmd/decrypt
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-darwin-amd64 ./cmd/genkey
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X file-crypto/internal/crypto.EmbeddedPublicKeyBase64=$(PUBKEY_B64) -X main.version=$(VERSION) -s -w" -o $(BUILD_DIR)/$(BINARY_NAME_ENCRYPT)-darwin-arm64 ./cmd/encrypt
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_DECRYPT)-darwin-arm64 ./cmd/decrypt
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME_GENKEY)-darwin-arm64 ./cmd/genkey

## Development Commands

.PHONY: run-encrypt
run-encrypt: ## Run encrypt with default settings
	go run ./cmd/encrypt -help

.PHONY: run-decrypt
run-decrypt: ## Run decrypt with default settings
	go run ./cmd/decrypt -help

.PHONY: run-genkey
run-genkey: ## Run genkey help
	go run ./cmd/genkey -h || true

.PHONY: run-builder
run-builder: ## Run interactive builder
	go run ./cmd/builder

.PHONY: test
test: ## Run tests
	go test -v ./...

.PHONY: test-race
test-race: ## Run tests with race detection
	go test -race -v ./...

.PHONY: bench
bench: ## Run benchmarks
	go test -bench=. -benchmem ./...

## Code Quality

.PHONY: fmt
fmt: ## Format code
	go fmt ./...

.PHONY: vet
vet: ## Vet code
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

.PHONY: check
check: fmt vet lint test ## Run all checks

## Utility Commands

.PHONY: clean
clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	go clean

.PHONY: deps
deps: ## Download and tidy dependencies
	go mod download
	go mod tidy

.PHONY: deps-update
deps-update: ## Update dependencies
	go get -u ./...
	go mod tidy

.PHONY: install
install: build ## Install binaries to GOPATH/bin
	@echo "📦 Installing binaries..."
	go install ./cmd/encrypt
	go install ./cmd/decrypt
	go install ./cmd/genkey

## Demo Commands

.PHONY: demo-setup
demo-setup: ## Set up demo environment
	@echo "🎬 Setting up demo environment..."
	@mkdir -p test
	@echo "This is a test file for encryption" > test/demo.txt
	@echo "Another test file with different content" > test/sample.txt
	@echo "Secret data that needs protection" > test/secret.txt
	@echo "demo_key_data_123456789" > decryption_key.txt
	@echo "✅ Demo files created in ./test/ directory"
	@echo "✅ Demo key created as decryption_key.txt"

.PHONY: demo-encrypt
demo-encrypt: build demo-setup ## Run encryption demo
	@echo "🔐 Running encryption demo..."
	./$(BUILD_DIR)/$(BINARY_NAME_ENCRYPT) -dir ./test -benchmark -verbose

.PHONY: demo-decrypt
demo-decrypt: build ## Run decryption demo (assumes encrypted files exist)
	@echo "🔓 Running decryption demo..."
	./$(BUILD_DIR)/$(BINARY_NAME_DECRYPT) -dir ./test -benchmark -verbose

.PHONY: demo-clean
demo-clean: ## Clean demo files
	@echo "🧹 Cleaning demo files..."
	rm -rf test/
	rm -f decryption_key.txt

## Help

.PHONY: help
help: ## Show this help message
	@echo "File Crypto - Go Implementation"
	@echo "================================"
	@echo ""
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*##"; printf ""} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""
	@echo "Examples:"
	@echo "  make build               # Build both binaries"
	@echo "  make build-encrypt-pub PUBKEY_B64=...   # Build encryptor with embedded public key"
	@echo "  make build-genkey        # Build genkey CLI to generate keys"
	@echo "  make build-builder       # Build the interactive builder"
	@echo "  make run-builder         # Run the interactive builder"
	@echo "  make build-linux         # Build Linux binaries"
	@echo "  make build-linux-pub PUBKEY_B64=...     # Build Linux encryptor with embedded key"
	@echo "  make build-windows-pub PUBKEY_B64=...   # Build Windows encryptor with embedded key"
	@echo "  make build-all-pub PUBKEY_B64=...       # Build ALL platforms with embedded key"
	@echo "  make demo-encrypt        # Run encryption demo"
	@echo "  make build-all           # Build for all platforms"
	@echo "  make check               # Run all code quality checks"

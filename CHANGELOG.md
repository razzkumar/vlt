# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Mask secret values in `run --dry-run` output to prevent accidental exposure
- Add path traversal protection to file write operations (reject `../` and absolute paths)
- Add TLS verification skip warning to stderr when `VAULT_SKIP_VERIFY=true` is used

### Changed

- Version is now injected at build time via `go build -ldflags "-X main.version=..."`

## [1.0.0] - 2024-02-27

### Added

**Core Secret Management**
- `put` command: Store single secrets or multiple key-value pairs in Vault KV v2
  - Support for `--value` flag or stdin input
  - `--from-env` for loading from .env files
  - `--from-file` for base64-encoding file content
  - Smart merging with existing multi-value secrets
  - Optional Transit encryption with `--encryption-key`

- `get` command: Retrieve secrets from Vault KV v2
  - Single value or multi-value retrieval
  - `--key` flag for extracting specific keys from multi-value secrets
  - JSON and .env format output
  - Automatic Transit decryption when encrypted

- `delete` command: Remove secrets from Vault
  - Single secret or all keys at a path
  - Confirmation prompts for safety

- `list` command: List secrets at a path in Vault KV v2

- `copy` command: Duplicate secrets between Vault paths
  - Preserves encryption status (encrypted secrets remain encrypted)
  - Supports copying single or multiple values

**Encryption & Key Management**
- Transit encryption engine integration (optional)
  - Secrets encrypted before storage when `--encryption-key` is provided
  - Automatic decryption on retrieval
  - Support for custom Transit mount paths
  - Plaintext storage option with `TRANSIT=false`

**Config-Driven Workflows**
- `sync` command: Sync secrets from YAML config to .env file
  - Declarative secret configuration
  - Required vs. optional secrets
  - Human-readable secret descriptions
  - Environment variable mapping

- `run` command: Execute commands with secrets injected as environment variables
  - Load secrets from YAML config
  - `--dry-run` to preview secret mapping without executing
  - Pass-through of remaining arguments

**Import/Export**
- `export` command: Export secrets to multiple formats
  - JSON format for programmatic use
  - .env format for shell environment sourcing
  - Encrypted or plaintext output

- `import` command: Import secrets from files
  - Load from JSON files
  - Load from .env files
  - Bulk secret creation

**Data Formats & Utilities**
- `json` command: Convert .env files to JSON
  - Optionally encrypt output with Transit
  - Standalone utility for format conversion

- `completion` command: Generate shell completions
  - bash
  - zsh
  - fish
  - powershell

**Authentication Methods**
- Token authentication (default)
- AppRole authentication (auto-detected from `VAULT_ROLE_ID` and `VAULT_SECRET_ID`)
- GitHub authentication (via personal access token)
- Kubernetes authentication (for in-cluster workloads)
- Automatic auth method detection based on environment variables

**Configuration Management**
- Environment variable support for all Vault settings
- YAML configuration files for declarative secret definitions
- Config validation with helpful error messages
- Support for custom KV and Transit mount paths
- Namespace support for isolated Vault environments

**Developer Experience**
- CLI help and usage text for all commands
- Clear error messages with remediation suggestions
- Quiet mode for scripts (`-q` / `--quiet`)
- Verbose output for debugging (`-v` / `--verbose`)
- Global flags for Vault address, token, and auth methods

**Build & Deployment**
- Cross-platform builds (Linux, macOS x86_64/ARM64, Windows)
- Docker support with multi-stage builds
- Makefile automation (build, test, install)
- Shell completion installation helpers

**Testing Infrastructure**
- Comprehensive test suite (table-driven tests)
- MockClient for dependency injection (in-memory KV store, call tracking)
- No external dependencies required for testing
- Coverage reporting support

### Limitations

- KV v2 secrets engine only (no KV v1 support)
- Single Vault instance per command (no cross-instance operations)
- No built-in secret rotation (use Vault's native rotation policies)

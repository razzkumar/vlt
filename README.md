# vlt

A minimal CLI tool for managing secrets with HashiCorp Vault, supporting optional Transit encryption.

## Features

- **11 commands**: put, get, delete, list, copy, export, import, sync, run, json, completion
- **Transit encryption**: Optionally encrypt secrets via Vault's Transit engine before storage
- **Config-driven workflows**: Define secrets in YAML, sync to `.env` files or inject into processes
- **Multiple auth methods**: Token, AppRole, GitHub, Kubernetes (auto-detected)
- **File storage**: Save secrets as files with configurable permissions
- **Smart merging**: Put operations merge with existing data by default

## Installation

### From Source

```bash
git clone https://github.com/razzkumar/vlt
cd vlt
make build
sudo mv vlt /usr/local/bin/
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/razzkumar/vlt/releases).

### Docker

```bash
docker build -t vlt .
docker run --rm -e VAULT_ADDR -e VAULT_TOKEN vlt get --path secrets/myapp
```

## Quick Start

```bash
# Set up Vault connection
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="hvs.your-token"

# Store a secret
vlt put --path secrets/db_password --value "supersecret"

# Retrieve it
vlt get --path secrets/db_password

# Store with Transit encryption
vlt put --encryption-key mykey --path secrets/db_password --value "supersecret"

# Retrieve and decrypt
vlt get --encryption-key mykey --path secrets/db_password

# Run a command with secrets injected
vlt run --config .vlt.yaml -- ./myapp
```

## Commands

### `put` (alias: `p`)

Store or update secrets in Vault. Merges with existing data by default.

```bash
# Store a single secret
vlt put --path secrets/db_password --value "supersecret"

# Store with Transit encryption
vlt put --encryption-key mykey --path secrets/db_password --value "supersecret"

# Update a specific key in a multi-value secret
vlt put --path secrets/myapp --key API_KEY --value "new-api-key"

# Store from .env file (merges with existing)
vlt put --encryption-key mykey --path secrets/myapp --env-file .env

# Store file as base64 (SSH keys, certificates)
vlt put --encryption-key mykey --path secrets/ssh_key --from-file ~/.ssh/id_rsa

# Overwrite instead of merging
vlt put --path secrets/myapp --env-file .env --force
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--path` | KV path to store secret(s) | *required* |
| `--value` | Secret value (or use stdin) | |
| `--key` | Specific key to update in multi-value secret | |
| `--encryption-key` | Transit encryption key name | |
| `--env-file` | Load key-value pairs from .env file | `.env` |
| `--from-file` | Load file content as base64 | |
| `--kv-mount` | KV v2 mount path | `home` |
| `--transit-mount` | Transit mount path | `transit` |
| `--force` | Overwrite existing data instead of merging | `false` |
| `--dry-run` | Show what would be done without changes | `false` |

### `get` (alias: `g`)

Retrieve and optionally decrypt secrets from Vault.

```bash
# Get all keys from a path
vlt get --path secrets/myapp

# Get a specific key
vlt get --path secrets/myapp --key API_KEY

# Get with decryption
vlt get --encryption-key mykey --path secrets/db_password

# Output as JSON
vlt get --path secrets/myapp --json

# Get raw value (no trailing newline, for piping)
vlt get --path secrets/myapp --key API_KEY --raw

# Provide a default if secret not found
vlt get --path secrets/myapp --key OPTIONAL --default "fallback"

# Get all secrets from config file
vlt get --config secrets.yaml

# Get from default config (.vlt.yaml)
vlt get
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--path` | KV path to retrieve | |
| `--config` | YAML config file | auto-detected |
| `--key` | Specific key to retrieve | |
| `--encryption-key` | Transit encryption key name | |
| `--json` | Output as JSON | `false` |
| `--raw` | Output raw value without newline | `false` |
| `--default` | Default value if not found | |
| `--kv-mount` | KV v2 mount path | `home` |
| `--transit-mount` | Transit mount path | `transit` |

### `delete` (aliases: `d`, `rm`)

Delete a secret from Vault.

```bash
vlt delete --path secrets/myapp/old-config
```

### `list` (alias: `ls`)

List secrets at a path. Directories shown with trailing `/`.

```bash
# List at root
vlt list

# List at a specific path
vlt list --path secrets/myapp
```

### `copy` (aliases: `c`, `cp`)

Copy secrets between paths.

```bash
# Copy a single path
vlt copy --from secrets/myapp/config --to secrets/myapp/config-backup

# Copy with overwrite
vlt copy --from secrets/app/v1 --to secrets/app/v2 --force

# Copy multiple paths from config
vlt copy --config copy-config.yaml
```

Config file format for bulk copy:
```yaml
copies:
  - from: secrets/app/config
    to: secrets/app/config-backup
  - from: secrets/db/creds
    to: secrets/db/creds-backup
```

### `export` (alias: `exp`)

Export secrets to a file.

```bash
# Export as JSON to stdout
vlt export --path secrets/myapp

# Export as .env format to file
vlt export --path secrets/myapp --format env --output .env

# Export with decryption
vlt export --path secrets/myapp --encryption-key mykey --output secrets.json
```

### `import` (alias: `imp`)

Import secrets from a file. Format auto-detected from extension.

```bash
# Import from JSON
vlt import --path secrets/myapp --input secrets.json

# Import from .env
vlt import --path secrets/myapp --input .env

# Import with encryption
vlt import --path secrets/myapp --input secrets.json --encryption-key mykey

# Merge with existing instead of replacing
vlt import --path secrets/myapp --input new.json --merge
```

### `sync` (alias: `s`)

Sync secrets from YAML config to `.env` file.

```bash
# Sync using default config (.vlt.yaml)
vlt sync

# Sync with specific config
vlt sync --config secrets.yaml

# Sync to custom output file
vlt sync --config secrets.yaml --output .env.local
```

### `run` (alias: `r`)

Run a command with secrets injected as environment variables.

```bash
# Run with config file
vlt run --config secrets.yaml -- go run main.go

# Run with default config (.vlt.yaml auto-detected)
vlt run -- ./myapp

# Inject specific secrets
vlt run --inject DB_PASSWORD=secrets/db_password --inject API_KEY=secrets/api_key -- npm start

# Combine config with .env file
vlt run --config secrets.yaml --env-file .env.local -- python app.py

# Dry run (shows masked variable names, does not execute)
vlt run --config secrets.yaml --dry-run

# Strict mode (fail if any secret can't be loaded)
vlt run --config secrets.yaml --strict -- ./myapp

# Add prefix to all injected variables
vlt run --config secrets.yaml --prefix APP_ -- ./myapp
```

### `json` (alias: `j`)

Convert `.env` file to JSON, optionally with Transit encryption.

```bash
# Plaintext JSON from default .env
vlt json

# Plaintext JSON from specific file
vlt json example.env

# Encrypted JSON (uses Transit)
TRANSIT=true vlt json

# Encrypted with custom key
vlt json --encryption-key mykey
```

### `completion` (alias: `comp`)

Generate shell completion scripts.

```bash
# Bash
vlt completion bash > /etc/bash_completion.d/vlt

# Zsh
vlt completion zsh > /usr/local/share/zsh/site-functions/_vlt

# Fish
vlt completion fish > ~/.config/fish/completions/vlt.fish

# PowerShell
vlt completion powershell > vlt.ps1
```

## Configuration

### Config File

vlt uses YAML config files. Search order: `VLT_CONFIG` env var, `./.vlt.yaml`, `~/.vlt.yaml`.

```yaml
vault:
  addr: "http://localhost:8200"
  # namespace: ""
  # skip_verify: false
  # ca_cert: "/path/to/ca.pem"

# Optional transit configuration (used when TRANSIT=true)
# transit:
#   mount: "transit"
#   key: "app-secrets"

kv:
  mount: "home"

# Optional file storage settings
# files:
#   output_dir: "./secrets"
#   default_mode: "0600"
#   create_dirs: true

secrets:
  # Load all keys from a path into env vars
  - path: "myapp/config"

  # Load a single key with custom env var name
  - path: "myapp/database"
    key: "password"
    env_key: "DB_PASSWORD"

  # Save a key as a file
  - path: "myapp/ssh"
    key: "id_rsa"
    file:
      path: "./secrets/id_rsa"
      mode: "0600"
      create_dir: true
```

See [`.vlt.example.yaml`](.vlt.example.yaml) for a complete example.

### Environment Variables

**Vault connection:**

| Variable | Description | Required |
|----------|-------------|----------|
| `VAULT_ADDR` | Vault server address | Yes |
| `VAULT_TOKEN` | Authentication token (for token auth) | Yes* |
| `VAULT_NAMESPACE` | Vault namespace | No |
| `VAULT_CACERT` | CA certificate path | No |
| `VAULT_SKIP_VERIFY` | Skip TLS verification | No |

**Transit encryption:**

| Variable | Description | Default |
|----------|-------------|---------|
| `TRANSIT` | Enable/disable transit: `true`/`false`, `1`/`0`, `yes`/`no` | `false` |
| `ENCRYPTION_KEY` | Transit encryption key name | `app-secrets` (when TRANSIT=true) |
| `TRANSIT_MOUNT` | Transit mount path | `transit` |

**Authentication (auto-detected based on which variables are set):**

| Variable | Auth Method |
|----------|-------------|
| `VAULT_TOKEN` | Token (default) |
| `VAULT_ROLE_ID` + `VAULT_SECRET_ID` | AppRole |
| `VAULT_GITHUB_TOKEN` | GitHub |
| `VAULT_K8S_ROLE` | Kubernetes |

Detection order: token > approle > github > kubernetes.

## Vault Setup

```bash
# Enable KV v2 secrets engine
vault secrets enable -path=home kv-v2

# (Optional) Enable Transit for encryption
vault secrets enable transit
vault write -f transit/keys/app-secrets
```

## Architecture

```
cmd/cli/main.go          Entry point, global flags
pkg/cli/
  commands.go             CLI command definitions
  completion.go           Shell completion generators
pkg/vault/
  interface.go            VaultClient interface
  client.go               Real Vault API implementation
  mock_client.go          Mock for testing
pkg/config/               Config structs, env var loading, YAML parsing, validation
internal/app/             Business logic (one file per command)
internal/utils/           Encryption helpers, file ops, output formatting
```

## Development

```bash
make build           # Build binary
make test            # Run tests
make test-race       # Run tests with race detector
make test-coverage   # Generate coverage report
make fmt             # Format code
make vet             # Static analysis
make deps            # Download and tidy dependencies
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full contributing guidelines.

## Documentation

- [Usage Guide](docs/GUIDE.md) — detailed walkthrough of all features
- [Contributing](CONTRIBUTING.md) — development setup and conventions
- [Security Policy](SECURITY.md) — vulnerability reporting
- [Changelog](CHANGELOG.md) — version history

## License

MIT License — see [LICENSE](LICENSE) for details.

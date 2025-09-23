# Configuration-Based File Storage for vlt get

This document describes the configuration-based file storage functionality for the `vlt get` command.

## Overview

The `vlt get` command supports configuration-based file handling where files are explicitly configured in the config file with a `file` section. This provides precise control over where files are saved, with what permissions, and whether to create directories.

## Configuration Structure

### Global File Storage Settings (Optional)

```yaml
files:
  output_dir: "./secrets"      # Default directory for files (default: ".")
  default_mode: "0600"         # Default file permissions (default: "0644")
  create_dirs: true           # Create directories if needed (default: true)
```

### Secret Configuration with File Support

```yaml
secrets:
  # Regular secret - loads all keys as environment variables
  - path: myapp/config

  # File secret with custom configuration
  - path: myapp/ssh
    key: private.pem           # Required for file entries
    file:
      path: "~/ssh/wp.pem"     # Supports ~ expansion, absolute/relative paths
      mode: "0600"             # Custom permissions (optional)
      create_dir: true         # Create directory if needed (optional)

  # File secret using global defaults
  - path: ssl/certificates
    key: server.crt
    file: {}                   # Uses global settings

  # Regular secret with custom env var name
  - path: myapp/database
    key: password
    env_key: DB_PASS          # Will be $DB_PASS instead of $PASSWORD
```

## Path Resolution

1. **Tilde expansion**: `~/path` expands to user home directory
2. **Absolute paths**: `/etc/ssl/certs/file.pem` used as-is
3. **Relative paths**: Resolved relative to global `output_dir` (if specified) or current directory

## Examples

### Basic Usage

```bash
# Use config file with file settings
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=root vlt get --config .vlt.yaml

# Get regular secrets from specific path
vlt get --path test/config

# Get specific key from multi-value secret
vlt get --path test/config --key database_password

# Output as JSON
vlt get --config .vlt.yaml --json
```

### Configuration Examples

#### Simple File Configuration
```yaml
vault:
  addr: "http://localhost:8200"
kv:
  mount: home

files:
  output_dir: "./secrets"
  default_mode: "0640"
  create_dirs: true

secrets:
  - path: test/config          # Environment variables
  - path: test/keys           # File with global settings
    key: api_key.txt
    file: {}
```

#### Advanced File Configuration
```yaml
vault:
  addr: "http://localhost:8200"
kv:
  mount: home

files:
  output_dir: "./secrets"
  default_mode: "0644"
  create_dirs: true

secrets:
  # Environment variables
  - path: myapp/config

  # File with custom path and strict permissions
  - path: ssl/certificates
    key: private.key
    file:
      path: "/etc/ssl/private/app.key"
      mode: "0600"
      create_dir: true

  # File in home directory
  - path: ssh/keys
    key: id_rsa
    file:
      path: "~/.ssh/app_rsa"
      mode: "0400"
      create_dir: true

  # File using global settings
  - path: configs/app
    key: config.json
    file: {}  # Uses ./secrets/config.json with mode 0644
```

## Key Features

- **Explicit configuration**: Files are only saved when explicitly configured with a `file` section
- **Per-file settings**: Each file can have custom path, permissions, and directory creation behavior
- **Global defaults**: Set default output directory, file permissions, and directory creation behavior
- **Path flexibility**: Supports tilde expansion (`~`), absolute paths, and relative paths
- **Environment variables**: Regular secrets without `file` configuration are loaded as environment variables

## Security Considerations

- Use restrictive permissions (e.g., `0600`, `0400`) for sensitive files like private keys
- Place sensitive files in secure locations (e.g., `/etc/ssl/private/`, `~/.ssh/`)
- The `create_dir` option will create directories with `0755` permissions

## File Permission Format

File permissions are specified as octal strings:
- `"0644"`: Owner read/write, group/others read
- `"0600"`: Owner read/write only
- `"0400"`: Owner read-only
- `"0755"`: Owner read/write/execute, group/others read/execute

## Working Example

With the test data in your local Vault:

```bash
# Set up environment
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root

# Get environment variables
vlt get --path test/config
# Output:
# API_KEY=test-api-key-123
# DATABASE_URL=postgres://localhost/myapp
# DEBUG=true

# Use config file to save files and get env vars
vlt get --config .vlt.demo.yaml
# Output:
# File saved: demo_output/certs/server.pem (mode: 0600)
# File saved: demo_output/api_key.txt (mode: 0640)
# File saved: /Users/razzkumar/demo_keys/private.key (mode: 0400)
# API_KEY=test-api-key-123
# DATABASE_URL=postgres://localhost/myapp
# DEBUG=true
```
# vlt Guide

Your single stop for using the `vlt` CLI to work with HashiCorp Vault. This guide consolidates the previous authentication, completion, file handling, JSON, and dependency docs into one place.

## Getting Started

1. Install and configure Vault (`kv` v2 and `transit` engines enabled) and make sure `VAULT_ADDR` plus your auth credentials are available in the environment.
2. Install `vlt` (e.g., `go install ./cmd/cli` or download a release) and confirm the binary is on your PATH.
3. Export a few common variables before you start:
   ```bash
   export VAULT_ADDR="https://vault.example.com:8200"
   export VAULT_TOKEN="hvs.xxxxxxxxxxxxx"    # or other supported auth inputs
   ```
4. Use `vlt put` to write secrets, `vlt get` to read them back, `vlt sync` to materialise .env files, and `vlt json` to produce JSON payloads.

## Authentication

`vlt` auto-detects Vault authentication based on the credentials you provide, checking in this order:

1. **Token** – `VAULT_TOKEN`
2. **AppRole** – `VAULT_ROLE_ID` + `VAULT_SECRET_ID`
3. **GitHub** – `VAULT_GITHUB_TOKEN`
4. **Kubernetes** – `VAULT_K8S_ROLE`

Override detection with `VAULT_AUTH_METHOD` (`token`, `approle`, `github`, `kubernetes`). Examples:

```bash
# AppRole
export VAULT_ROLE_ID="00275ac3-734f-49fc-0f46-5e9a76fbf304"
export VAULT_SECRET_ID="282cb405-42e9-c709-bd9f-030998e3f8e8"
vlt get --path secrets/app

# GitHub
export VAULT_GITHUB_TOKEN="ghp_xxxxxxxxxxxxx"
vlt get --path secrets/app

# Kubernetes
export VAULT_K8S_ROLE="my-app-role"
vlt get --path secrets/app
```

Reference Vault setup commands:

```bash
# Enable auth methods
vault auth enable approle
vault auth enable github
vault auth enable kubernetes

# Retrieve ids / configure mappings
vault read auth/approle/role/vlt-app/role-id
vault write -f auth/approle/role/vlt-app/secret-id
vault write auth/github/config organization=myorg
vault write auth/kubernetes/role/vlt-app \
  bound_service_account_names=vlt \
  bound_service_account_namespaces=default \
  policies=vlt-policy \
  ttl=24h
```

You can also provide most values via CLI flags (e.g., `vlt --vault-addr ... get --path ...`).

## Working With Secrets

- **Store values**: `vlt put --path myapp/config --env-file production.env` or `vlt put --path myapp/ssh --from-file ~/.ssh/id_rsa`.
- **Retrieve values**: `vlt get --path myapp/config --json` or `vlt get --path myapp/kv --key cert.pem`.
- **Copy values**: `vlt copy --from myapp/config --to backups/myapp/config` or `vlt copy --from myapp --to backups/myapp --recursive`.
- **Generate .env**: `vlt sync --config .vlt.yaml --output .env`.

Transit encryption follows `TRANSIT`/`ENCRYPTION_KEY`/`TRANSIT_MOUNT` rules: set `TRANSIT=true` to force encryption (defaults key to `app-secrets` and mount to `transit`).

## Copy Between Vaults

`vlt copy` can write to another Vault instance by supplying destination-specific flags or env vars:

```bash
vlt copy \
  --from myapp \
  --to backups/myapp \
  --recursive \
  --kv-mount source \
  --dest-kv-mount dr-secrets \
  --dest-vault-addr https://vault-dr.example.com:8200 \
  --dest-vault-token hvs.dr-token
```

Equivalent destination env vars are available: `DEST_VAULT_ADDR`, `DEST_VAULT_TOKEN`, `DEST_VAULT_NAMESPACE`, `DEST_VAULT_AUTH_METHOD`, `DEST_VAULT_ROLE_ID`, `DEST_VAULT_SECRET_ID`, `DEST_VAULT_GITHUB_TOKEN`, `DEST_VAULT_K8S_ROLE`, and `DEST_KV_MOUNT`.

Behavior notes:
- Missing destination mounts are created automatically as KV v2.
- Recursive copy preserves relative paths under the destination root.
- Values are copied raw; encrypted ciphertext is not decrypted or re-encrypted.
- Without `--force`, copy stops at the first destination conflict. Recursive copy is not transactional, so earlier writes are not rolled back.

## File Storage From Config or Metadata

`vlt get` supports saving Vault keys to disk when told to do so either by config or metadata.

### Global File Settings

```yaml
files:
  output_dir: "./secrets"    # defaults to current directory
  default_mode: "0600"       # defaults to "0600"
  create_dirs: true          # defaults to true
```

### Secret Entries

```yaml
secrets:
  - path: myapp/config  # regular env vars

  - path: myapp/ssh
    key: private.pem
    file:
      path: "~/ssh/wp.pem"
      mode: "0600"
      create_dir: true

  - path: ssl/certificates
    key: server.crt
    file: {}  # inherits global defaults
```

When a matching config exists, `vlt get --config ...` or `vlt get --path ... --key ...` writes the key to the configured location, creating directories if allowed. Without config, metadata created by `vlt put --from-file` keeps compatibility by saving in the current directory.

### Tips

- Relative paths resolve against `files.output_dir`.
- Use restrictive modes (`0600`, `0400`) for sensitive material.
- Created directories default to `0700` when enabled.
- The command prints where files land, e.g. `File saved: ./secrets/server.crt (mode: 0600)`.

## JSON Command

`vlt json [FILE]` converts a `.env` file to JSON. Encryption is controlled by `TRANSIT` and optional overrides:

```bash
# Plaintext JSON from default .env
vlt json

# Plaintext from specific file
vlt json example.env

# Encrypted JSON using defaults (key "app-secrets", mount "transit")
TRANSIT=true vlt json

# Custom key / mount
TRANSIT=true ENCRYPTION_KEY=mykey TRANSIT_MOUNT=custom-transit vlt json example.env

# Force plaintext even when key is present
TRANSIT=false ENCRYPTION_KEY=mykey vlt json
```

Use cases: feeding configuration systems, CI/CD pipelines, or generating encrypted payloads for backup.

## Shell Completions

Generate shell completion scripts with `vlt completion <shell>`:

```bash
# Fish
vlt completion fish > ~/.config/fish/completions/vlt.fish
source ~/.config/fish/completions/vlt.fish

# Bash
mkdir -p ~/.bash_completion.d
vlt completion bash > ~/.bash_completion.d/vlt
echo 'source ~/.bash_completion.d/vlt' >> ~/.bashrc

# Zsh
mkdir -p ~/.zsh/completions
vlt completion zsh > ~/.zsh/completions/_vlt
echo 'fpath=(~/.zsh/completions $fpath)' >> ~/.zshrc
echo 'autoload -U compinit && compinit' >> ~/.zshrc

# PowerShell
vlt completion powershell > vlt-completion.ps1
Add-Content $PROFILE ". path/to/vlt-completion.ps1"
```

Troubleshooting tips:
- **Fish**: verify `~/.config/fish/completions/vlt.fish`, reload with `source`.
- **Bash**: ensure `bash-completion` is installed; check `complete -p vlt`.
- **Zsh**: rebuild cache via `rm -f ~/.zcompdump; compinit`.
- **PowerShell**: confirm execution policy allows scripts and `$PROFILE` references the script.

## Dependency Management

`go.mod` pins the following key dependencies (Go 1.25.0):
- `github.com/hashicorp/vault/api` v1.22.0
- `github.com/urfave/cli/v2` v2.27.7
- `github.com/joho/godotenv` v1.5.1

### Update Strategy

The Vault API depends on a forked HCL version (`v1.0.1-vault-7`). To avoid conflicts:

```bash
# Update non-Vault dependencies first
go get -u github.com/urfave/cli/v2 github.com/joho/godotenv

# Then update the Vault API allowing it to pick compatible transitive deps
go get -u github.com/hashicorp/vault/api@latest

go mod tidy
```

Validate with:

```bash
make build
make test
./vlt --version
```

Keep an eye on security advisories, and log the Go toolchain version used for releases.

## Troubleshooting & Tips

- If `go test` fails due to module proxy access, set `GOPROXY=direct` or populate a local module cache.
- Run `TRANSIT=true` whenever you want encryption by default; use `TRANSIT=false` to force plaintext.
- Metadata is preserved when using `vlt put --from-file`, so older secrets continue to download as files even without explicit config.

---

Need something that is not covered here? Open an issue or check `README.md` for architectural details.

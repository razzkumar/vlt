# Contributing to vlt

Thank you for your interest in contributing to vlt! This guide explains how to set up your development environment, understand the codebase, and submit contributions.

## Prerequisites

- **Go 1.21 or later** - [Install Go](https://golang.org/doc/install)
- **Git** - For version control and cloning the repository
- **HashiCorp Vault instance** - For manual testing (optional, but recommended for testing encryption features)
  - Running locally: `vault server -dev` (development mode)
  - Or use a remote Vault instance for integration testing

## Development Setup

1. **Clone the repository**

```bash
git clone https://github.com/razzkumar/vlt
cd vlt
```

2. **Download dependencies**

```bash
make deps
# or: go mod download && go mod tidy
```

3. **Build the binary**

```bash
make build
# Creates: ./vlt
```

4. **Run tests to verify setup**

```bash
make test
# All tests should pass
```

## Project Structure

Understanding the layout helps you know where to make changes:

```
vlt/
├── cmd/cli/main.go              # Entry point, defines global flags and CLI app
├── pkg/
│   ├── cli/commands.go          # All 11 command definitions (put, get, delete, list, export, import, sync, run, json, copy, completion)
│   ├── vault/
│   │   ├── interface.go         # VaultClient interface (Encrypt, Decrypt, KV CRUD)
│   │   ├── client.go            # Real Vault API implementation
│   │   └── mock_client.go       # Mock client for testing (in-memory KV + call tracking)
│   └── config/
│       ├── config.go            # Config structs, env var loading, YAML parsing, validation
│       └── constants.go         # Constants and defaults
├── internal/
│   ├── app/
│   │   ├── app.go               # App struct holding VaultClient; constructors
│   │   ├── put.go, get.go, delete.go, etc.  # One file per command's business logic
│   │   └── *_test.go            # Co-located tests (table-driven)
│   └── utils/
│       ├── encryption.go        # Transit encryption helpers
│       ├── errors.go            # Error collection and handling
│       ├── format.go            # Output formatting (JSON, .env)
│       └── file.go              # File operations
└── Makefile                     # Build automation
```

**Key data flow:**
CLI layer (cmd/cli/main.go) parses flags → creates options → calls App.Method() → App uses VaultClient interface → formats and outputs result.

**Dependency injection:**
App holds a VaultClient interface. Production uses vault.Client (real API). Tests use vault.MockClient which tracks calls and stores data in-memory.

## Adding a New Command

To add a new command (e.g., `vlt newcmd`):

1. **Create handler in `internal/app/newcmd.go`**

```go
package app

import (
	"github.com/razzkumar/vlt/pkg/vault"
)

func (a *App) NewCmd(path string, options ...interface{}) (string, error) {
	// Business logic here
	// Use a.Client (VaultClient interface) for Vault operations
	return result, nil
}
```

2. **Add command definition in `pkg/cli/commands.go`**

```go
func getNewCmdCommand() *cli.Command {
	return &cli.Command{
		Name:    "newcmd",
		Usage:   "Description of what this command does",
		Aliases: []string{"nc"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "path",
				Usage:    "KV path",
				Required: true,
			},
		},
		Action: func(ctx *cli.Context) error {
			client, err := vault.NewClient()
			if err != nil {
				return err
			}
			a := app.New(client)
			result, err := a.NewCmd(ctx.String("path"))
			if err != nil {
				return err
			}
			fmt.Println(result)
			return nil
		},
	}
}
```

3. **Add command to `GetCommands()` slice** in pkg/cli/commands.go

4. **Write tests in `internal/app/newcmd_test.go`** (see Testing Conventions below)

5. **Update main.go if new global flags are needed** (cmd/cli/main.go)

## Testing Conventions

All tests use table-driven subtests with the mock client. No live Vault needed.

1. **Test file naming:** `*_test.go` in the same package as the code being tested
2. **Test function naming:** `Test<ThingUnderTest>` (e.g., `TestPutCommand`)
3. **Mock usage:** All command tests inject `vault.MockClient` via `app.NewWithClient(mockClient)`

Example test structure:

```go
func TestPutCommand(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		value   string
		mockErr error
		want    string
		wantErr bool
	}{
		{
			name:  "put single value",
			path:  "secrets/db",
			value: "password123",
			want:  "secrets/db: stored",
		},
		{
			name:    "put with error",
			path:    "secrets/db",
			value:   "password123",
			mockErr: errors.New("vault error"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &vault.MockClient{}
			if tt.mockErr != nil {
				mockClient.KVPutError = tt.mockErr
			}
			a := app.NewWithClient(mockClient)

			result, err := a.Put(tt.path, tt.value)

			if (err != nil) != tt.wantErr {
				t.Errorf("Put() error = %v, wantErr %v", err, tt.wantErr)
			}
			if result != tt.want {
				t.Errorf("Put() = %q, want %q", result, tt.want)
			}
		})
	}
}
```

Run tests:

```bash
make test              # Run all tests
make test-race         # Run with race detector (find concurrency bugs)
go test -run TestName ./internal/app/  # Run a specific test
```

## Code Style

1. **Formatting:** Use `gofmt` (standard Go formatter)

```bash
make fmt
# or: go fmt ./...
```

2. **Static analysis:** Use `go vet`

```bash
make vet
# or: go vet ./...
```

3. **Naming conventions:**
   - Packages: lowercase (`vault`, `config`, `app`)
   - Exported: CamelCase (`Put`, `Get`, `VaultClient`)
   - Private: mixedCaps (`kvPath`, `clientErr`)

4. **Commits:** Use [Conventional Commits](https://www.conventionalcommits.org/)
   - `feat: add copy command for duplicating secrets between paths`
   - `fix: default permissions for .env file`
   - `chore: update dependencies`
   - Keep subject line under 72 characters
   - Use imperative mood ("add" not "added")

## PR Process

1. **Fork the repository** on GitHub
2. **Create a feature branch**

```bash
git checkout -b feat/your-feature-name
```

3. **Make your changes**
   - Write code following conventions above
   - Add tests for new functionality
   - Update README.md if user-facing changes

4. **Test locally**

```bash
make fmt
make vet
make test
```

5. **Commit with conventional commits**

```bash
git commit -m "feat: add my feature"
```

6. **Push and create a pull request**

```bash
git push origin feat/your-feature-name
```

7. **PR requirements:**
   - All tests pass
   - Code is formatted with gofmt
   - Commit messages follow Conventional Commits
   - Include a description of what changed and why

## Common Development Tasks

**Run a single test:**

```bash
go test -run TestPutCommand ./internal/app/
```

**Generate coverage report:**

```bash
make test-coverage
# Opens coverage.html
```

**Build for all platforms:**

```bash
make build-all
# Creates binaries: vlt-linux-amd64, vlt-darwin-amd64, vlt-darwin-arm64, vlt-windows-amd64.exe
```

**Test with a real Vault instance (optional):**

```bash
# Start dev Vault
vault server -dev

# In another terminal
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="<token from server output>"

# Test a command
./vlt put --path secrets/test --value "hello" --encryption-key mykey
./vlt get --path secrets/test --encryption-key mykey
```

## Need Help?

- Check [README.md](README.md) for usage examples
- Review existing command implementations in `internal/app/` for patterns
- Open a GitHub issue with questions or feature requests

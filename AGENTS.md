# Repository Guidelines

## Project Structure & Module Organization
The CLI entrypoint lives in `cmd/cli`, while reusable libraries sit under `pkg` (configuration, Vault client, and CLI wiring). Core business flows reside in `internal/app`, with shared helpers in `internal/utils`. Example configs and docs live in `docs/` and `example.env`; temporary artifacts should go in `tmp/`. Place new Go packages alongside related code and co-locate tests as `<name>_test.go` within the same directory.

## Build, Test, and Development Commands
Use `make build` (or `go build ./cmd/cli`) to compile the `vlt` binary locally. `make deps` runs `go mod download` and `go mod tidy` to keep module metadata in sync. Execute `make test` or `go test ./...` before sending changes, and prefer `go test -race ./...` when touching concurrent code paths. `make fmt` and `make vet` are the fastest way to apply `gofmt` and `go vet` across the tree.

## Coding Style & Naming Conventions
All Go files must be formatted with `gofmt` (tabs for indentation, trailing newline). Follow idiomatic Go naming: packages use short lowercase names (`vault`, `config`), exported symbols use `CamelCase`, and private helpers stay in `mixedCaps`. When adding CLI commands, mirror existing patterns in `pkg/cli` (constructor functions named `new<Command>Command`). Avoid committing generated binaries; `.gitignore` already covers the compiled `vlt` executable.

## Testing Guidelines
Author table-driven tests where practical and name them `Test<ThingUnderTest>`. Keep fixtures lightweight and prefer in-memory fakes over hitting a live Vault. Run `go test ./...` from the repo root before every push; include `-run` filters only for local iteration. If you modify serialization or parsing logic, add assertions that cover both success and failure paths.

## Commit & Pull Request Guidelines
This project uses Conventional Commits (`feat:`, `fix:`, `chore:`) as seen in `git log`. Write messages in imperative mood and keep the subject under 72 characters. Pull requests should describe the change, reference the relevant issue, and list the commands used for verification (e.g., `make test`). Include screenshots or sample CLI output when altering user-facing behavior.

## Security & Configuration Tips
Never commit real Vault tokens or Transit keys; rely on `example.env` or redacted snippets for documentation. Store local secrets in `.env` files outside version control and use `vlt put --from-env` for bulk loads. When testing against a shared Vault instance, use disposable namespaces and note any required setup in the PR description.

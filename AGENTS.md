# AGENTS.md

This file provides guidance for agentic coding agents working with the Wraith vulnerability classification system.

## Build/Test/Lint Commands
- **Build**: `go build -o process ./cmd/process` or `go build -o report ./cmd/report` or `go build -o debug ./cmd/debug`
- **Test**: `go test ./...` (single package: `go test ./internal/classifier`)
- **Format**: `go fmt ./...`
- **Vet**: `go vet ./...`
- **Lint**: Use `golangci-lint run` if available
- **Run**: `go run ./cmd/process` or `go run ./cmd/report` or `go run ./cmd/debug`

## Code Style Guidelines
- **Imports**: Standard library first, then external packages, then internal packages with blank line separation
- **Naming**: Use camelCase for local variables, PascalCase for exported types/functions
- **Error handling**: Always check errors immediately, use `fmt.Errorf` with `%w` verb for wrapping
- **Comments**: Only add when explicitly requested - focus on clear, self-documenting code
- **Struct tags**: Use both `json` and `firestore` tags for data structures that persist to storage
- **Types**: Prefer explicit types over inference where it improves clarity

## Project Structure
- `cmd/process/`: Process vulnerabilities from OSV database
- `cmd/report/`: Generate report of processed vulnerabilities  
- `cmd/debug/`: Test custom prompts with LLM classifier
- `internal/classifier/`: LLM-based vulnerability classification logic
- `internal/config/`: YAML configuration loading with sensible defaults
- `internal/downloader/`: OSV database vulnerability fetching
- `internal/storage/`: Firestore persistence layer
- No existing test framework detected - use standard Go testing when adding tests

## JSON Schema usage
This project uses `github.com/swaggest/jsonschema-go` which uses standard Go `json` struct tags. Do not use `github.com/invopop/jsonschema` and do not add `jsonschema` tags to structs.

This is a security-focused project for analyzing vulnerability data - maintain careful handling of external data and API credentials.

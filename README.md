# VScan - Vulnerability Scanner and Classifier

VScan is a Go application that downloads vulnerability data from OSV.dev and classifies vulnerabilities using a 6-dimensional system with the help of Large Language Models (LLMs).

## Features

- Downloads vulnerability data from OSV.dev using the modified_id.csv approach
- Processes vulnerabilities in configurable batches (default: 100)
- Supports multiple LLM providers (OpenAI, Anthropic, Vertex AI)
- Stores classifications in Google Cloud Firestore
- Resumable processing with automatic checkpoint saving
- Flexible configuration system

## 6-Dimensional Classification System

Each vulnerability is classified across these dimensions:

1. **Verifiability**: Can the vulnerability be objectively confirmed in code?
2. **Exploitability Context**: Direct/transitive dependency, dev-only, or runtime-critical?
3. **Attack Vector Accessibility**: Network, local, user input required, or config-dependent?
4. **Impact Scope**: Confidentiality, integrity, availability, code execution, or privilege escalation?
5. **Remediation Complexity**: Simple update, breaking change, no fix, workaround, or architecture change?
6. **Temporal Classification**: Zero-day, active exploitation, stable/mature, or legacy?

## Installation

```bash
git clone https://github.com/ghostsecurity/vscan
cd vscan
go mod tidy
```

## Configuration

Copy the example configuration:

```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml` with your settings:

```yaml
firestore:
  project_id: "your-gcp-project-id"
  collection: "vulnerability_classifications"

llm:
  provider: "openai"
  model: "gpt-4"
  api_key: "your-api-key-here"

osv:
  ecosystem: "npm"  # Optional: filter by ecosystem
```

## Usage

Process vulnerabilities:
```bash
go run ./cmd/process
```

Generate reports:
```bash
go run ./cmd/report
```

Debug with custom prompts:
```bash
go run ./cmd/debug
```

Commands support standard Go flags - use `-h` for help on each command.

## LLM Provider Configuration

### OpenAI
```yaml
llm:
  provider: "openai"
  model: "gpt-4"
  api_key: "sk-..."
```

### Anthropic
```yaml
llm:
  provider: "anthropic"
  model: "claude-3-haiku-20240307"
  api_key: "sk-ant-..."
```

### Google Vertex AI
```yaml
llm:
  provider: "vertex"
  model: "gemini-pro"
  options:
    project_id: "your-gcp-project"
    location: "us-central1"
```

## Authentication

### Google Cloud Firestore
Ensure you have appropriate GCP credentials:
- Set `GOOGLE_APPLICATION_CREDENTIALS` environment variable
- Or use `gcloud auth application-default login`
- Or run on GCP with appropriate service account

### LLM Providers
- **OpenAI**: Set API key in configuration
- **Anthropic**: Set API key in configuration  
- **Vertex AI**: Use GCP authentication (same as Firestore)

## Output

Classifications are stored in Firestore with this structure:
```json
{
  "vulnerability_id": "GHSA-xxxx-xxxx-xxxx",
  "verifiability": "verifiable",
  "exploitability_context": "runtime-critical",
  "attack_vector": "network-accessible",
  "impact_scope": "code-execution",
  "remediation_complexity": "simple-update",
  "temporal_classification": "stable-mature",
  "reasoning": "Explanation of classification decisions",
  "processed_at": "2024-01-15T10:30:00Z"
}
```

## Progress Tracking

The application automatically saves progress to Firestore in the `processing_state` collection, allowing for resumable processing across runs.

## Development

Build the applications:
```bash
go build -o process ./cmd/process
go build -o report ./cmd/report
go build -o debug ./cmd/debug
```

Run tests:
```bash
go test ./...
```
package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ghostsecurity/vscan/internal/downloader"
)

// Classification represents our 6-dimensional vulnerability classification
type Classification struct {
	VulnerabilityID string `json:"vulnerability_id" firestore:"vulnerability_id"`

	// 1. Verifiability
	Verifiability string `json:"verifiability" firestore:"verifiability"` // verifiable, non-verifiable, partially-verifiable

	// 2. Exploitability Context
	ExploitabilityContext string `json:"exploitability_context" firestore:"exploitability_context"` // direct-dependency, transitive-dependency, development-only, runtime-critical

	// 3. Attack Vector Accessibility
	AttackVector string `json:"attack_vector" firestore:"attack_vector"` // user-input-required, network-accessible, local-only, configuration-dependent

	// 4. Impact Scope
	ImpactScope string `json:"impact_scope" firestore:"impact_scope"` // data-confidentiality, data-integrity, system-availability, code-execution, privilege-escalation

	// 5. Remediation Complexity
	RemediationComplexity string `json:"remediation_complexity" firestore:"remediation_complexity"` // simple-update, breaking-change, no-fix-available, workaround-available, architecture-change

	// 6. Temporal Classification
	TemporalClassification string `json:"temporal_classification" firestore:"temporal_classification"` // zero-day, active-exploitation, stable-mature, legacy

	// Additional metadata
	Reasoning   string `json:"reasoning" firestore:"reasoning"`
	ProcessedAt string `json:"processed_at" firestore:"processed_at"`
}

type Classifier struct {
	llmClient LLMClient
}

func New(llmClient LLMClient) *Classifier {
	return &Classifier{
		llmClient: llmClient,
	}
}

func (c *Classifier) Classify(ctx context.Context, vuln *downloader.Vulnerability) (*Classification, error) {
	prompt := c.buildClassificationPrompt(vuln)

	messages := []Message{
		{
			Role:    "system",
			Content: systemPrompt,
		},
		{
			Role:    "user",
			Content: prompt,
		},
	}

	response, err := c.llmClient.Chat(ctx, messages)
	if err != nil {
		return nil, fmt.Errorf("LLM classification failed: %w", err)
	}

	classification, err := c.parseClassificationResponse(response.Content, vuln.ID)
	if err != nil {
		return nil, fmt.Errorf("parsing classification response: %w", err)
	}

	return classification, nil
}

func (c *Classifier) buildClassificationPrompt(vuln *downloader.Vulnerability) string {
	var builder strings.Builder

	builder.WriteString("Please classify this vulnerability using our 6-dimensional system:\n\n")

	builder.WriteString(fmt.Sprintf("Vulnerability ID: %s\n", vuln.ID))
	builder.WriteString(fmt.Sprintf("Summary: %s\n", vuln.Summary))

	if vuln.Details != "" {
		builder.WriteString(fmt.Sprintf("Details: %s\n", vuln.Details))
	}

	if len(vuln.Aliases) > 0 {
		builder.WriteString(fmt.Sprintf("Aliases: %s\n", strings.Join(vuln.Aliases, ", ")))
	}

	if len(vuln.Affected) > 0 {
		builder.WriteString("Affected packages:\n")
		for _, affected := range vuln.Affected {
			builder.WriteString(fmt.Sprintf("- %s (%s)\n", affected.Package.Name, affected.Package.Ecosystem))
		}
	}

	if len(vuln.References) > 0 {
		builder.WriteString("References:\n")
		for i, ref := range vuln.References {
			if i < 3 { // Limit to first 3 references to avoid token limit
				builder.WriteString(fmt.Sprintf("- %s: %s\n", ref.Type, ref.URL))
			}
		}
	}

	if len(vuln.Severity) > 0 {
		builder.WriteString("Severity scores:\n")
		for _, severity := range vuln.Severity {
			builder.WriteString(fmt.Sprintf("- %s: %s\n", severity.Type, severity.Score))
		}
	}

	return builder.String()
}

func (c *Classifier) parseClassificationResponse(response, vulnID string) (*Classification, error) {
	// Try to extract JSON from the response
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")

	if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
		return nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]

	var classification Classification
	if err := json.Unmarshal([]byte(jsonStr), &classification); err != nil {
		return nil, fmt.Errorf("unmarshaling JSON: %w", err)
	}

	// Validate required fields
	if err := c.validateClassification(&classification); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	classification.VulnerabilityID = vulnID
	classification.ProcessedAt = time.Now().Format(time.RFC3339)

	return &classification, nil
}

func (c *Classifier) validateClassification(classification *Classification) error {
	validValues := map[string][]string{
		"verifiability":           {"verifiable", "non-verifiable", "partially-verifiable"},
		"exploitability_context":  {"direct-dependency", "transitive-dependency", "development-only", "runtime-critical"},
		"attack_vector":           {"user-input-required", "network-accessible", "local-only", "configuration-dependent"},
		"impact_scope":            {"data-confidentiality", "data-integrity", "system-availability", "code-execution", "privilege-escalation"},
		"remediation_complexity":  {"simple-update", "breaking-change", "no-fix-available", "workaround-available", "architecture-change"},
		"temporal_classification": {"zero-day", "active-exploitation", "stable-mature", "legacy"},
	}

	fields := map[string]string{
		"verifiability":           classification.Verifiability,
		"exploitability_context":  classification.ExploitabilityContext,
		"attack_vector":           classification.AttackVector,
		"impact_scope":            classification.ImpactScope,
		"remediation_complexity":  classification.RemediationComplexity,
		"temporal_classification": classification.TemporalClassification,
	}

	for field, value := range fields {
		if value == "" {
			return fmt.Errorf("missing required field: %s", field)
		}

		valid := false
		for _, validValue := range validValues[field] {
			if value == validValue {
				valid = true
				break
			}
		}

		if !valid {
			return fmt.Errorf("invalid value for %s: %s (valid: %v)", field, value, validValues[field])
		}
	}

	return nil
}

const systemPrompt = `You are an expert security analyst specializing in vulnerability classification. Your task is to classify software vulnerabilities using a 6-dimensional system.

For each vulnerability, you must classify it across these 6 dimensions:

1. **Verifiability**:
   - verifiable: Objective code/config patterns can confirm presence (e.g., specific function names, configuration settings)
   - non-verifiable: Requires behavioral analysis or complex logic inspection
   - partially-verifiable: Some indicators present but incomplete confirmation possible

2. **Exploitability Context**:
   - direct-dependency: Vulnerability in directly imported package
   - transitive-dependency: Vulnerability in sub-dependency
   - development-only: Only affects dev/test environments
   - runtime-critical: Affects production execution paths

3. **Attack Vector Accessibility**:
   - user-input-required: Needs malicious user input to trigger
   - network-accessible: Exploitable via network requests
   - local-only: Requires local file system access
   - configuration-dependent: Only exploitable with specific configs

4. **Impact Scope**:
   - data-confidentiality: Information disclosure/leakage
   - data-integrity: Data modification/corruption
   - system-availability: DoS/service disruption
   - code-execution: RCE/arbitrary code execution
   - privilege-escalation: Authentication/authorization bypass

5. **Remediation Complexity**:
   - simple-update: Direct version bump fixes issue
   - breaking-change: Update requires code modifications
   - no-fix-available: Vulnerability unpatched
   - workaround-available: Mitigation possible without update
   - architecture-change: Requires significant refactoring

6. **Temporal Classification**:
   - zero-day: Recently disclosed, patches may not be widely available
   - active-exploitation: Known to be exploited in the wild
   - stable-mature: Well-documented with established remediation
   - legacy: Old vulnerability in deprecated component

Respond with a JSON object containing your classification and reasoning:

{
  "verifiability": "value",
  "exploitability_context": "value", 
  "attack_vector": "value",
  "impact_scope": "value",
  "remediation_complexity": "value",
  "temporal_classification": "value",
  "reasoning": "Brief explanation of your classification decisions"
}

Focus on objective analysis based on the vulnerability details provided.`

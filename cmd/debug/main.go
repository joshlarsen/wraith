package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ghostsecurity/wraith/internal/classifier"
	"github.com/ghostsecurity/wraith/internal/config"
	"github.com/ghostsecurity/wraith/internal/downloader"
)

func main() {
	debugFlags := flag.NewFlagSet("debug", flag.ExitOnError)
	configPath := debugFlags.String("config", "config.yaml", "Path to configuration file")
	prompt := debugFlags.String("prompt", "", "Custom prompt to test with classifier")
	vulnID := debugFlags.String("vuln", "", "Vulnerability ID to use for testing (fetches from OSV)")
	samplePath := debugFlags.String("sample", "", "Path to JSON file containing vulnerability data")
	debugFlags.Parse(os.Args[1:])

	if *prompt == "" {
		fmt.Println("Usage: debug -prompt \"your custom prompt here\" [-vuln VULN_ID] [-sample path/to/sample.json]")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -config     Path to configuration file (default: config.yaml)")
		fmt.Println("  -prompt     Custom prompt to test with the LLM")
		fmt.Println("  -vuln       Vulnerability ID to fetch from OSV API")
		fmt.Println("  -sample     Path to JSON file with vulnerability data")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  debug -prompt \"Analyze this vulnerability for RCE potential\" -vuln GHSA-xxxx-xxxx-xxxx")
		fmt.Println("  debug -prompt \"Custom classification prompt\" -sample samples/npm-GHSA-7rqq-prvp-x9jh.json")
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx := context.Background()

	// Initialize LLM client
	llmClient, err := classifier.NewLLMClient(&cfg.LLM)
	if err != nil {
		log.Fatalf("Failed to initialize LLM client: %v", err)
	}

	var vuln *downloader.Vulnerability

	// Determine data source
	switch {
	case *vulnID != "":
		// Fetch vulnerability from OSV API
		log.Printf("Fetching vulnerability %s from OSV API...", *vulnID)
		osvDownloader := downloader.New(&cfg.OSV)
		fetchedVuln, err := osvDownloader.FetchVulnerability(ctx, *vulnID)
		if err != nil {
			log.Fatalf("Failed to fetch vulnerability from OSV: %v", err)
		}
		vuln = fetchedVuln

	case *samplePath != "":
		// Load from JSON file
		log.Printf("Loading vulnerability from %s...", *samplePath)
		loadedVuln, err := loadVulnerabilityFromFile(*samplePath)
		if err != nil {
			log.Fatalf("Failed to load vulnerability from file: %v", err)
		}
		vuln = loadedVuln

	default:
		log.Fatal("Must specify either -vuln or -sample to provide vulnerability data")
	}

	log.Printf("Using vulnerability: %s", vuln.ID)
	log.Printf("Custom prompt: %s", *prompt)

	// Create a custom classifier with the debug prompt
	debugClassifier := &DebugClassifier{
		llmClient:    llmClient,
		customPrompt: *prompt,
	}

	// Run classification
	log.Println("Running custom classification...")
	result, err := debugClassifier.ClassifyWithCustomPrompt(ctx, vuln)
	if err != nil {
		log.Fatalf("Classification failed: %v", err)
	}

	// Print results
	fmt.Println("\n=== DEBUG CLASSIFICATION RESULTS ===")
	fmt.Printf("Vulnerability ID: %s\n", vuln.ID)
	fmt.Printf("Processing Time: %v\n", result.ProcessingTime)
	fmt.Printf("Input Tokens: %d\n", result.InputTokens)
	fmt.Printf("Output Tokens: %d\n", result.OutputTokens)
	fmt.Printf("Total Tokens: %d\n", result.TotalTokens)
	fmt.Println()
	fmt.Println("=== LLM Response ===")
	fmt.Println(result.RawResponse)
	fmt.Println()
}

type DebugClassifier struct {
	llmClient    classifier.LLMClient
	customPrompt string
}

type DebugResult struct {
	ProcessingTime time.Duration
	InputTokens    int
	OutputTokens   int
	TotalTokens    int
	RawResponse    string
}

func (dc *DebugClassifier) ClassifyWithCustomPrompt(ctx context.Context, vuln *downloader.Vulnerability) (*DebugResult, error) {
	// Build the prompt with vulnerability data
	vulnData := fmt.Sprintf(`
Vulnerability ID: %s
Summary: %s
Details: %s
Aliases: %s
References: %s
Affected Packages: %s
`,
		vuln.ID,
		vuln.Summary,
		vuln.Details,
		strings.Join(vuln.Aliases, ", "),
		strings.Join(extractURLs(vuln.References), ", "),
		formatAffected(vuln.Affected))

	fullPrompt := fmt.Sprintf("%s\n\nVulnerability Data:\n%s", dc.customPrompt, vulnData)

	// Use the LLM client to get a response
	start := time.Now()
	messages := []classifier.Message{{Role: "user", Content: fullPrompt}}
	response, err := dc.llmClient.Chat(ctx, messages)
	processingTime := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("LLM completion failed: %w", err)
	}

	return &DebugResult{
		ProcessingTime: processingTime,
		InputTokens:    response.InputTokens,
		OutputTokens:   response.OutputTokens,
		TotalTokens:    response.TotalTokens,
		RawResponse:    response.Content,
	}, nil
}

func loadVulnerabilityFromFile(filePath string) (*downloader.Vulnerability, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var vuln downloader.Vulnerability
	if err := json.Unmarshal(data, &vuln); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &vuln, nil
}

func extractURLs(refs []struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}) []string {
	var urls []string
	for _, ref := range refs {
		if ref.URL != "" {
			urls = append(urls, ref.URL)
		}
	}
	return urls
}

func formatAffected(affected []struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced,omitempty"`
			Fixed      string `json:"fixed,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
}) string {
	var result []string
	for _, pkg := range affected {
		result = append(result, fmt.Sprintf("%s (%s)", pkg.Package.Name, pkg.Package.Ecosystem))
	}
	return strings.Join(result, ", ")
}

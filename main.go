package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ghostsecurity/wraith/internal/classifier"
	"github.com/ghostsecurity/wraith/internal/config"
	"github.com/ghostsecurity/wraith/internal/downloader"
	"github.com/ghostsecurity/wraith/internal/storage"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "process":
		runProcessCommand()
	case "report":
		runReportCommand()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: wraith <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  process  Process vulnerabilities from OSV database")
	fmt.Println("  report   Generate report of all processed vulnerabilities")
	fmt.Println()
	fmt.Println("Use 'wraith <command> -h' for command-specific help")
}

func runProcessCommand() {
	processFlags := flag.NewFlagSet("process", flag.ExitOnError)
	configPath := processFlags.String("config", "config.yaml", "Path to configuration file")
	resume := processFlags.Bool("resume", false, "Resume from last processed timestamp")
	batchSize := processFlags.Int("batch", 100, "Number of vulnerabilities to process in each batch")
	processFlags.Parse(os.Args[2:])

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx := context.Background()

	// Initialize components
	storage, err := storage.NewFirestore(ctx, &cfg.Firestore)
	if err != nil {
		log.Fatalf("Failed to initialize Firestore: %v", err)
	}
	defer storage.Close()

	llmClient, err := classifier.NewLLMClient(&cfg.LLM)
	if err != nil {
		log.Fatalf("Failed to initialize LLM client: %v", err)
	}

	classifier := classifier.New(llmClient, &cfg.OSV)
	downloader := downloader.New(&cfg.OSV)

	// Get last processed timestamp if resuming
	var lastTimestamp string
	if *resume {
		lastTimestamp, err = storage.GetLastProcessedTimestamp(ctx)
		if err != nil {
			log.Printf("Warning: Failed to get last timestamp, starting from beginning: %v", err)
		}
	}

	// Start processing
	processor := &VulnerabilityProcessor{
		downloader:    downloader,
		classifier:    classifier,
		storage:       storage,
		batchSize:     *batchSize,
		lastTimestamp: lastTimestamp,
	}

	if err := processor.Run(ctx); err != nil {
		log.Fatalf("Processing failed: %v", err)
		os.Exit(1)
	}

	// Print final summary
	if processor.processedCount > 0 {
		avgProcessingTime := processor.totalProcessingTime / time.Duration(processor.processedCount)
		avgTokensPerVuln := processor.totalTokens / processor.processedCount
		log.Printf("=== FINAL SUMMARY ===")
		log.Printf("Total vulnerabilities processed: %d", processor.processedCount)
		log.Printf("Average processing time: %v", avgProcessingTime)
		log.Printf("Average tokens per vulnerability: %d", avgTokensPerVuln)
		log.Printf("Total tokens used: %d", processor.totalTokens)
		log.Printf("Total processing time: %v", processor.totalProcessingTime)
	}

	log.Println("Processing completed successfully")
}

func runReportCommand() {
	reportFlags := flag.NewFlagSet("report", flag.ExitOnError)
	configPath := reportFlags.String("config", "config.yaml", "Path to configuration file")
	outputPath := reportFlags.String("output", "vulnerability_report.json", "Output file path for the report")
	reportFlags.Parse(os.Args[2:])

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx := context.Background()

	// Initialize Firestore storage
	storage, err := storage.NewFirestore(ctx, &cfg.Firestore)
	if err != nil {
		log.Fatalf("Failed to initialize Firestore: %v", err)
	}
	defer storage.Close()

	log.Printf("Fetching all processed vulnerabilities from Firestore...")

	// Get all vulnerabilities
	vulnerabilities, err := storage.GetAllClassifications(ctx)
	if err != nil {
		log.Fatalf("Failed to fetch vulnerabilities: %v", err)
	}

	if len(vulnerabilities) == 0 {
		log.Printf("No vulnerabilities found in database")
		return
	}

	log.Printf("Found %d vulnerabilities, writing to %s", len(vulnerabilities), *outputPath)

	// Write to JSON file
	file, err := os.Create(*outputPath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(vulnerabilities); err != nil {
		log.Fatalf("Failed to write JSON: %v", err)
	}

	log.Printf("Report generated successfully: %s", *outputPath)
}

type VulnerabilityProcessor struct {
	downloader    *downloader.Downloader
	classifier    *classifier.Classifier
	storage       storage.Storage
	batchSize     int
	lastTimestamp string

	// Metrics tracking
	totalProcessingTime time.Duration
	totalTokens         int
	processedCount      int
}

func (p *VulnerabilityProcessor) Run(ctx context.Context) error {
	log.Printf("Starting vulnerability processing with batch size %d", p.batchSize)

	if p.lastTimestamp != "" {
		log.Printf("Resuming from timestamp: %s", p.lastTimestamp)
	}

	return p.downloader.ProcessVulnerabilities(ctx, p.lastTimestamp, p.batchSize, p.processVulnerability)
}

func (p *VulnerabilityProcessor) processVulnerability(ctx context.Context, vuln *downloader.Vulnerability) error {
	// Classify the vulnerability using LLM
	classification, err := p.classifier.Classify(ctx, vuln)
	if err != nil {
		log.Printf("Failed to classify vulnerability %s: %v", vuln.ID, err)
		return err
	}

	// Store in Firestore
	if err := p.storage.StoreClassification(ctx, vuln.ID, classification); err != nil {
		log.Printf("Failed to store classification for %s: %v", vuln.ID, err)
		return err
	}

	// Update progress marker
	if err := p.storage.UpdateLastProcessedTimestamp(ctx, vuln.Modified); err != nil {
		log.Printf("Failed to update timestamp: %v", err)
		return err
	}

	// Update metrics tracking
	p.totalProcessingTime += classification.ProcessingTime
	p.totalTokens += classification.TotalTokens
	p.processedCount++

	log.Printf("Processed vulnerability: %s [%v : ↑ %dt / ↓ %dt (%dt), pub: %s]",
		vuln.ID,
		classification.ProcessingTime,
		classification.InputTokens,
		classification.OutputTokens,
		classification.TotalTokens,
		classification.OSVPublished)

	// Print periodic summary every 10 vulnerabilities
	if p.processedCount%10 == 0 {
		avgProcessingTime := p.totalProcessingTime / time.Duration(p.processedCount)
		avgTokensPerVuln := p.totalTokens / p.processedCount
		log.Printf("--- Summary: %d vulnerabilities processed | Avg processing: %v | Avg tokens: %d | Total tokens: %d ---",
			p.processedCount, avgProcessingTime, avgTokensPerVuln, p.totalTokens)
	}

	return nil
}

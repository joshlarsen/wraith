package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/ghostsecurity/wraith/internal/classifier"
	"github.com/ghostsecurity/wraith/internal/config"
	"github.com/ghostsecurity/wraith/internal/downloader"
	"github.com/ghostsecurity/wraith/internal/storage"
)

func main() {
	var (
		configPath = flag.String("config", "config.yaml", "Path to configuration file")
		resume     = flag.Bool("resume", false, "Resume from last processed timestamp")
		batchSize  = flag.Int("batch", 100, "Number of vulnerabilities to process in each batch")
	)
	flag.Parse()

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
		avgProcessingTime := processor.totalProcessingTimeMs / int64(processor.processedCount)
		avgTokensPerVuln := processor.totalTokens / processor.processedCount
		log.Printf("=== FINAL SUMMARY ===")
		log.Printf("Total vulnerabilities processed: %d", processor.processedCount)
		log.Printf("Average processing time: %dms", avgProcessingTime)
		log.Printf("Average tokens per vulnerability: %d", avgTokensPerVuln)
		log.Printf("Total tokens used: %d", processor.totalTokens)
		log.Printf("Total processing time: %.2fs", float64(processor.totalProcessingTimeMs)/1000.0)
	}

	log.Println("Processing completed successfully")
}

type VulnerabilityProcessor struct {
	downloader    *downloader.Downloader
	classifier    *classifier.Classifier
	storage       storage.Storage
	batchSize     int
	lastTimestamp string

	// Metrics tracking
	totalProcessingTimeMs int64
	totalTokens           int
	processedCount        int
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
	p.totalProcessingTimeMs += classification.ProcessingTimeMs
	p.totalTokens += classification.TotalTokens
	p.processedCount++

	log.Printf("Processed vulnerability: %s (processing: %dms, tokens: %d input/%d output/%d total, published: %s)",
		vuln.ID,
		classification.ProcessingTimeMs,
		classification.InputTokens,
		classification.OutputTokens,
		classification.TotalTokens,
		classification.OSVPublished)

	// Print periodic summary every 10 vulnerabilities
	if p.processedCount%10 == 0 {
		avgProcessingTime := p.totalProcessingTimeMs / int64(p.processedCount)
		avgTokensPerVuln := p.totalTokens / p.processedCount
		log.Printf("--- Summary: %d vulnerabilities processed | Avg processing: %dms | Avg tokens: %d | Total tokens: %d ---",
			p.processedCount, avgProcessingTime, avgTokensPerVuln, p.totalTokens)
	}

	return nil
}

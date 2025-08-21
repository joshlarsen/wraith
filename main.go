package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/ghostsecurity/vscan/internal/classifier"
	"github.com/ghostsecurity/vscan/internal/config"
	"github.com/ghostsecurity/vscan/internal/downloader"
	"github.com/ghostsecurity/vscan/internal/storage"
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

	classifier := classifier.New(llmClient)
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

	log.Println("Processing completed successfully")
}

type VulnerabilityProcessor struct {
	downloader    *downloader.Downloader
	classifier    *classifier.Classifier
	storage       storage.Storage
	batchSize     int
	lastTimestamp string
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

	log.Printf("Processed vulnerability: %s", vuln.ID)
	return nil
}

package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/ghostsecurity/wraith/internal/config"
	"github.com/ghostsecurity/wraith/internal/storage"
)

func main() {
	reportFlags := flag.NewFlagSet("report", flag.ExitOnError)
	configPath := reportFlags.String("config", "config.yaml", "Path to configuration file")
	outputPath := reportFlags.String("output", "vulnerability_report.json", "Output file path for the report")
	reportFlags.Parse(os.Args[1:])

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

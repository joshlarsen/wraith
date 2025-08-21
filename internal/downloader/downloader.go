package downloader

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ghostsecurity/wraith/internal/config"
)

type Downloader struct {
	config *config.OSVConfig
	client *http.Client
}

type Vulnerability struct {
	ID        string   `json:"id"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Withdrawn string   `json:"withdrawn,omitempty"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Affected  []struct {
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
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
	Severity         []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

type CSVRecord struct {
	Modified  string
	Ecosystem string
	VulnID    string
	FullPath  string
}

func New(cfg *config.OSVConfig) *Downloader {
	return &Downloader{
		config: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (d *Downloader) ProcessVulnerabilities(ctx context.Context, lastTimestamp string, batchSize int, processFunc func(context.Context, *Vulnerability) error) error {
	records, err := d.downloadCSV(ctx)
	if err != nil {
		return fmt.Errorf("downloading CSV: %w", err)
	}

	batch := make([]*CSVRecord, 0, batchSize)
	processed := 0

	for _, record := range records {
		// Skip if we've already processed this timestamp
		if lastTimestamp != "" && record.Modified <= lastTimestamp {
			continue
		}

		// Filter by ecosystem if specified
		if d.config.Ecosystem != "" && record.Ecosystem != d.config.Ecosystem {
			continue
		}

		batch = append(batch, record)

		if len(batch) >= batchSize {
			if err := d.processBatch(ctx, batch, processFunc); err != nil {
				return fmt.Errorf("processing batch: %w", err)
			}
			processed += len(batch)
			fmt.Printf("Processed %d vulnerabilities\n", processed)
			batch = batch[:0] // Reset batch
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	// Process remaining records
	if len(batch) > 0 {
		if err := d.processBatch(ctx, batch, processFunc); err != nil {
			return fmt.Errorf("processing final batch: %w", err)
		}
		processed += len(batch)
	}

	fmt.Printf("Total processed: %d vulnerabilities\n", processed)
	return nil
}

func (d *Downloader) downloadCSV(ctx context.Context) ([]*CSVRecord, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", d.config.ModifiedCSVURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading CSV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	reader := csv.NewReader(resp.Body)
	var records []*CSVRecord

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading CSV: %w", err)
		}

		if len(row) != 2 {
			continue // Skip malformed rows
		}

		fullPath := row[1]
		parts := strings.SplitN(fullPath, "/", 2)
		if len(parts) != 2 {
			continue // Skip malformed paths
		}

		records = append(records, &CSVRecord{
			Modified:  row[0],
			Ecosystem: parts[0],
			VulnID:    parts[1],
			FullPath:  fullPath,
		})
	}

	return records, nil
}

func (d *Downloader) processBatch(ctx context.Context, batch []*CSVRecord, processFunc func(context.Context, *Vulnerability) error) error {
	for _, record := range batch {
		vuln, err := d.fetchVulnerability(ctx, record.VulnID)
		if err != nil {
			fmt.Printf("Warning: Failed to fetch vulnerability %s: %v\n", record.VulnID, err)
			continue
		}

		vuln.Modified = record.Modified // Ensure we have the CSV timestamp

		if err := processFunc(ctx, vuln); err != nil {
			return fmt.Errorf("processing vulnerability %s: %w", record.VulnID, err)
		}
	}
	return nil
}

func (d *Downloader) fetchVulnerability(ctx context.Context, vulnID string) (*Vulnerability, error) {
	url := fmt.Sprintf("%s/vulns/%s", d.config.APIURL, vulnID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching vulnerability: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	var vuln Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("decoding vulnerability: %w", err)
	}

	return &vuln, nil
}

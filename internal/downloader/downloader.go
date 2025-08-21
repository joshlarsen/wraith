package downloader

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

type CacheMetadata struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	CachedAt     time.Time `json:"cached_at"`
	TTL          int       `json:"ttl_hours"`
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
	cacheKey := d.generateCacheKey(d.config.ModifiedCSVURL)
	cachePath := filepath.Join(d.config.CacheDir, cacheKey+".csv")
	metadataPath := filepath.Join(d.config.CacheDir, cacheKey+".meta.json")

	// Try to load from cache first
	if records, valid := d.loadFromCache(cachePath, metadataPath); valid {
		fmt.Println("Using cached CSV data")
		return records, nil
	}

	fmt.Println("Downloading fresh CSV data")
	return d.downloadAndCache(ctx, cachePath, metadataPath)
}

func (d *Downloader) generateCacheKey(url string) string {
	h := sha256.New()
	h.Write([]byte(url))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func (d *Downloader) loadFromCache(cachePath, metadataPath string) ([]*CSVRecord, bool) {
	// Check if cache files exist
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return nil, false
	}
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		return nil, false
	}

	// Load and validate metadata
	metaData, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, false
	}

	var meta CacheMetadata
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return nil, false
	}

	// Check if cache is expired
	if d.config.CacheTTL > 0 {
		expireTime := meta.CachedAt.Add(time.Duration(d.config.CacheTTL) * time.Hour)
		if time.Now().After(expireTime) {
			return nil, false
		}
	}

	// Load cached CSV data
	file, err := os.Open(cachePath)
	if err != nil {
		return nil, false
	}
	defer file.Close()

	records, err := d.parseCSV(file)
	if err != nil {
		return nil, false
	}

	return records, true
}

func (d *Downloader) downloadAndCache(ctx context.Context, cachePath, metadataPath string) ([]*CSVRecord, error) {
	// Ensure cache directory exists
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

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

	// Create temporary file to store downloaded content
	tmpFile, err := os.CreateTemp(filepath.Dir(cachePath), "csv_download_*.tmp")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Copy response to temp file
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("copying CSV data: %w", err)
	}

	// Parse CSV from temp file
	if _, err := tmpFile.Seek(0, 0); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("seeking temp file: %w", err)
	}

	records, err := d.parseCSV(tmpFile)
	tmpFile.Close()
	if err != nil {
		return nil, err
	}

	// Save to cache
	if err := d.saveToCache(tmpFile.Name(), cachePath, metadataPath, resp.Header); err != nil {
		fmt.Printf("Warning: Failed to save to cache: %v\n", err)
	}

	return records, nil
}

func (d *Downloader) parseCSV(reader io.Reader) ([]*CSVRecord, error) {
	csvReader := csv.NewReader(reader)
	var records []*CSVRecord

	for {
		row, err := csvReader.Read()
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

func (d *Downloader) saveToCache(tmpPath, cachePath, metadataPath string, headers http.Header) error {
	// Move temp file to cache location
	if err := os.Rename(tmpPath, cachePath); err != nil {
		return fmt.Errorf("moving temp file to cache: %w", err)
	}

	// Save metadata
	meta := CacheMetadata{
		URL:          d.config.ModifiedCSVURL,
		ETag:         headers.Get("ETag"),
		LastModified: headers.Get("Last-Modified"),
		CachedAt:     time.Now(),
		TTL:          d.config.CacheTTL,
	}

	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, metaData, 0644); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}

	return nil
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

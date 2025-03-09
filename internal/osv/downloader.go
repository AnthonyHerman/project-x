package osv

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AnthonyHerman/project-x/internal/database"
)

// Supported ecosystems for LLM function analysis
var InScopeEcosystems = []string{
	"PyPI",
	"npm",
	"Go",
	"Maven",
	"RubyGems",
	"crates.io",
	"Hex",
	"NuGet",
	"Packagist",
	"Pub",
	"Haskell",
}

// OSVDownloader handles downloading and processing OSV data files
type OSVDownloader struct {
	db              *database.DB
	tempDir         string
	osvStorageURL   string
	networkDelay    time.Duration // Delay for network requests only
}

// NewOSVDownloader creates a new OSV downloader instance
func NewOSVDownloader(db *database.DB) *OSVDownloader {
	return &OSVDownloader{
		db:              db,
		tempDir:         os.TempDir(),
		osvStorageURL:   "https://osv-vulnerabilities.storage.googleapis.com",
		networkDelay:    100 * time.Millisecond, // Prevent rate limiting for network requests
	}
}

// DownloadAndProcessEcosystems downloads and processes all in-scope ecosystems
func (d *OSVDownloader) DownloadAndProcessEcosystems() error {
	log.Printf("Starting download and processing of %d ecosystems", len(InScopeEcosystems))
	
	// Create a working directory
	workDir, err := os.MkdirTemp(d.tempDir, "osv-data-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(workDir)
	
	// Process each ecosystem
	for _, ecosystem := range InScopeEcosystems {
		if err := d.processEcosystem(ecosystem, workDir); err != nil {
			log.Printf("Error processing ecosystem %s: %v", ecosystem, err)
			// Continue with other ecosystems even if one fails
		}
		
		// Short delay between ecosystem downloads to avoid rate limiting
		time.Sleep(d.networkDelay)
	}
	
	return nil
}

// processEcosystem downloads and processes a single ecosystem's vulnerabilities
func (d *OSVDownloader) processEcosystem(ecosystem, workDir string) error {
	log.Printf("Processing ecosystem: %s", ecosystem)
	
	// Download the ecosystem data
	zipPath := filepath.Join(workDir, fmt.Sprintf("%s.zip", ecosystem))
	url := fmt.Sprintf("%s/%s/all.zip", d.osvStorageURL, ecosystem)
	
	if err := d.downloadFile(url, zipPath); err != nil {
		return fmt.Errorf("failed to download %s: %w", url, err)
	}
	
	// Extract the zip file
	extractDir := filepath.Join(workDir, ecosystem)
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", extractDir, err)
	}
	
	log.Printf("Extracting %s to %s", zipPath, extractDir)
	startTime := time.Now()
	if err := d.extractZip(zipPath, extractDir); err != nil {
		return fmt.Errorf("failed to extract %s: %w", zipPath, err)
	}
	log.Printf("Extraction completed in %v", time.Since(startTime))
	
	// Load the data into the database
	loader := NewLoader(d.db)
	if err := loader.LoadFromPath(extractDir); err != nil {
		return fmt.Errorf("failed to load data from %s: %w", extractDir, err)
	}
	
	log.Printf("Successfully processed ecosystem: %s", ecosystem)
	return nil
}

// downloadFile downloads a file from a URL to a local path
func (d *OSVDownloader) downloadFile(url, destPath string) error {
	log.Printf("Downloading %s to %s", url, destPath)
	startTime := time.Now()
	
	// Create the file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", destPath, err)
	}
	defer out.Close()
	
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	
	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	
	// Write the body to file
	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save response body to %s: %w", destPath, err)
	}
	
	log.Printf("Downloaded %d bytes in %v", written, time.Since(startTime))
	return nil
}

// extractZip extracts a zip file to a directory
func (d *OSVDownloader) extractZip(zipPath, destDir string) error {
	// Open the zip file
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip %s: %w", zipPath, err)
	}
	defer r.Close()
	
	// Log the number of files to extract
	log.Printf("Extracting %d files from %s", len(r.File), filepath.Base(zipPath))
	
	// Extract each file
	for i, f := range r.File {
		// Prevent path traversal vulnerabilities
		destPath := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", f.Name)
		}
		
		if f.FileInfo().IsDir() {
			// Create directory
			if err := os.MkdirAll(destPath, f.Mode()); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", destPath, err)
			}
			continue
		}
		
		// Create parent directory if needed
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("failed to create parent directory for %s: %w", destPath, err)
		}
		
		// Extract file
		if err := d.extractFile(f, destPath); err != nil {
			return err
		}
		
		// Log progress periodically
		if i > 0 && i%5000 == 0 {
			log.Printf("Extracted %d/%d files from %s", i, len(r.File), filepath.Base(zipPath))
		}
	}
	
	return nil
}

// extractFile extracts a single file from a zip archive
func (d *OSVDownloader) extractFile(f *zip.File, destPath string) error {
	// Open file in zip
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("failed to open file in zip: %w", err)
	}
	defer rc.Close()
	
	// Create destination file
	outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", destPath, err)
	}
	defer outFile.Close()
	
	// Copy contents
	_, err = io.Copy(outFile, rc)
	if err != nil {
		return fmt.Errorf("failed to extract file contents to %s: %w", destPath, err)
	}
	
	return nil
}

// QueueVulnerabilitiesForAnalysis finds vulnerabilities without function data
// for in-scope ecosystems and adds them to the analysis queue
func (d *OSVDownloader) QueueVulnerabilitiesForAnalysis() error {
	log.Println("Queueing vulnerabilities for LLM analysis")
	
	// Build ecosystem list for SQL
	placeholders := make([]string, len(InScopeEcosystems))
	args := make([]interface{}, len(InScopeEcosystems))
	
	for i, eco := range InScopeEcosystems {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = eco
	}
	
	// Find vulnerabilities without function data
	query := fmt.Sprintf(`
		INSERT INTO analysis_queue (vuln_id)
		SELECT id FROM vulnerabilities
		WHERE ecosystem IN (%s)
		AND has_function_data = false
		AND id NOT IN (SELECT vuln_id FROM analysis_queue)
	`, strings.Join(placeholders, ","))
	
	result, err := d.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to queue vulnerabilities: %w", err)
	}
	
	rows, _ := result.RowsAffected()
	log.Printf("Queued %d vulnerabilities for analysis", rows)
	
	return nil
}

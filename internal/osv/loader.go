package osv

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/AnthonyHerman/project-x/internal/database"
	"github.com/AnthonyHerman/project-x/internal/osv/models"
)

type Loader struct {
	db *database.DB
}

func NewLoader(db *database.DB) *Loader {
	return &Loader{db: db}
}

// LoadFromPath loads all OSV files from the specified path
func (l *Loader) LoadFromPath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	log.Printf("Starting to load OSV data from %s", path)

	// Start a transaction
	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	var processed, failed int
	err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error accessing path %s: %v", path, err)
			return err
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		processed++
		if err := l.processFile(tx, path); err != nil {
			log.Printf("Error processing file %s: %v", path, err)
			failed++
			return err // Stop processing on first error
		}

		if processed%100 == 0 {
			log.Printf("Processed %d files, %d failures", processed, failed)
		}
		return nil
	})

	if err != nil {
		log.Printf("Error during OSV data processing: %v", err)
		return fmt.Errorf("failed while processing OSV data: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("Successfully processed %d files with %d failures", processed, failed)
	return nil
}

func (l *Loader) processFile(tx database.Tx, path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading file %s: %w", path, err)
	}

	var entry models.Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return fmt.Errorf("error parsing JSON from %s: %w", path, err)
	}

	// Validate entry
	if entry.ID == "" {
		return fmt.Errorf("vulnerability in %s has no ID", path)
	}

	if len(entry.Affected) == 0 {
		log.Printf("Skipping %s: no affected packages", entry.ID)
		return nil
	}

	// Check for function data
	hasFunc := false
	for _, affected := range entry.Affected {
		if len(affected.EcosystemSpecific.Imports) > 0 {
			hasFunc = true
			break
		}
	}

	// Insert vulnerability
	if err = l.insertVulnerability(tx, &entry, hasFunc, data); err != nil {
		return fmt.Errorf("failed to insert vulnerability %s: %w", entry.ID, err)
	}

	// Insert version information
	if err = l.insertVersions(tx, &entry); err != nil {
		return fmt.Errorf("failed to insert versions for %s: %w", entry.ID, err)
	}

	// Insert functions or queue for analysis
	if hasFunc {
		if err = l.insertFunctions(tx, &entry); err != nil {
			return fmt.Errorf("failed to insert functions for %s: %w", entry.ID, err)
		}
	} else {
		if err = l.queueForAnalysis(tx, entry.ID); err != nil {
			return fmt.Errorf("failed to queue for analysis %s: %w", entry.ID, err)
		}
	}

	return nil
}

func (l *Loader) insertVulnerability(tx database.Tx, entry *models.Entry, hasFunc bool, rawData []byte) error {
	result, err := tx.Exec(`
		INSERT INTO vulnerabilities 
		(id, ecosystem, package, summary, details, has_function_data, raw_data)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET
			ecosystem = EXCLUDED.ecosystem,
			package = EXCLUDED.package,
			summary = EXCLUDED.summary,
			details = EXCLUDED.details,
			has_function_data = EXCLUDED.has_function_data,
			raw_data = EXCLUDED.raw_data,
			updated_at = CURRENT_TIMESTAMP
	`, entry.ID, entry.Affected[0].Package.Ecosystem, entry.Affected[0].Package.Name,
		entry.Summary, entry.Details, hasFunc, rawData)

	if err != nil {
		return fmt.Errorf("database error inserting vulnerability: %w", err)
	}

	rows, _ := result.RowsAffected()
	log.Printf("Vulnerability %s: %d rows affected", entry.ID, rows)
	return nil
}

func (l *Loader) insertFunctions(tx database.Tx, entry *models.Entry) error {
	for _, affected := range entry.Affected {
		for _, imp := range affected.EcosystemSpecific.Imports {
			for _, symbol := range imp.Symbols {
				_, err := tx.Exec(`
					INSERT INTO vulnerable_functions
					(vuln_id, package_path, function_name, source_type, verified)
					VALUES ($1, $2, $3, 'osv', true)
					ON CONFLICT (vuln_id, package_path, function_name) DO UPDATE SET
						source_type = EXCLUDED.source_type,
						verified = EXCLUDED.verified,
						updated_at = CURRENT_TIMESTAMP
				`, entry.ID, imp.Path, symbol)

				if err != nil {
					return fmt.Errorf("error inserting function %s.%s: %w", imp.Path, symbol, err)
				}
			}
		}
	}
	return nil
}

func (l *Loader) insertVersions(tx database.Tx, entry *models.Entry) error {
	for _, affected := range entry.Affected {
		for _, r := range affected.Ranges {
			if r.Type != "SEMVER" {
				continue
			}

			var introduced, fixed string
			for _, event := range r.Events {
				if event.Introduced != "" {
					introduced = event.Introduced
				}
				if event.Fixed != "" {
					fixed = event.Fixed
				}
			}

			var versionRange string
			if introduced == "0" || introduced == "" {
				versionRange = ">= 0"
			} else {
				versionRange = fmt.Sprintf(">= %s", introduced)
			}
			if fixed != "" {
				versionRange += fmt.Sprintf(", < %s", fixed)
			}

			_, err := tx.Exec(`
				INSERT INTO affected_versions
				(vuln_id, version_range, fixed_version, package_path)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (vuln_id, package_path) DO UPDATE SET
					version_range = EXCLUDED.version_range,
					fixed_version = EXCLUDED.fixed_version,
					updated_at = CURRENT_TIMESTAMP
			`, entry.ID, versionRange, fixed, affected.Package.Name)

			if err != nil {
				return fmt.Errorf("error inserting version range for %s: %w", entry.ID, err)
			}
		}
	}
	return nil
}

func (l *Loader) queueForAnalysis(tx database.Tx, vulnID string) error {
	_, err := tx.Exec(`
		INSERT INTO analysis_queue (vuln_id)
		VALUES ($1)
		ON CONFLICT (vuln_id) DO UPDATE SET
			attempts = 0,
			last_attempt = NULL,
			error_log = NULL,
			updated_at = CURRENT_TIMESTAMP
	`, vulnID)

	if err != nil {
		return fmt.Errorf("error queueing for analysis: %w", err)
	}
	return nil
}

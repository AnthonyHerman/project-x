package database

import (
	"fmt"
)

// Bootstrap initializes the database schema if it doesn't exist
func Bootstrap() error {
	db, err := Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Define the schema
	schema := `
	-- Base vulnerability information
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		ecosystem TEXT NOT NULL,
		package TEXT NOT NULL,
		summary TEXT,
		details TEXT,
		published_date TIMESTAMP,
		has_function_data BOOLEAN DEFAULT false,
		needs_analysis BOOLEAN DEFAULT true,
		last_analyzed TIMESTAMP,
		raw_data JSONB,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);
	-- Store version ranges for vulnerabilities
	CREATE TABLE IF NOT EXISTS affected_versions (
		id SERIAL PRIMARY KEY,
		vuln_id TEXT REFERENCES vulnerabilities(id),
		version_range TEXT NOT NULL,
		fixed_version TEXT,
		package_path TEXT NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(vuln_id, package_path)
	);
	-- Store known vulnerable functions
	CREATE TABLE IF NOT EXISTS vulnerable_functions (
		id SERIAL PRIMARY KEY,
		vuln_id TEXT REFERENCES vulnerabilities(id),
		package_path TEXT NOT NULL,
		function_name TEXT NOT NULL,
		source_type TEXT NOT NULL, -- 'osv', 'llm', 'manual'
		confidence FLOAT,
		verified BOOLEAN DEFAULT false,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(vuln_id, package_path, function_name)
	);
	-- Analysis queue for vulnerabilities without function data
	CREATE TABLE IF NOT EXISTS analysis_queue (
		vuln_id TEXT PRIMARY KEY REFERENCES vulnerabilities(id),
		priority INTEGER DEFAULT 0,
		attempts INTEGER DEFAULT 0,
		last_attempt TIMESTAMP WITH TIME ZONE,
		error_log TEXT,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);
	-- Create indexes for common queries
	CREATE INDEX IF NOT EXISTS idx_vuln_package ON vulnerabilities(package);
	CREATE INDEX IF NOT EXISTS idx_vuln_ecosystem ON vulnerabilities(ecosystem);
	CREATE INDEX IF NOT EXISTS idx_vuln_has_function_data ON vulnerabilities(has_function_data);
	CREATE INDEX IF NOT EXISTS idx_vuln_needs_analysis ON vulnerabilities(needs_analysis);
	CREATE INDEX IF NOT EXISTS idx_vuln_functions ON vulnerable_functions(package_path, function_name);
	CREATE INDEX IF NOT EXISTS idx_vuln_functions_source ON vulnerable_functions(source_type);
	CREATE INDEX IF NOT EXISTS idx_analysis_queue_priority ON analysis_queue(priority, attempts);

	-- Add last_download tracking for OSV data
	CREATE TABLE IF NOT EXISTS metadata (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);
	`

	// Execute the schema
	_, err = db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

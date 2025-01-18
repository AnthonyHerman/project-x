# Runtime SCA with eBPF

A runtime Software Composition Analysis (SCA) tool using eBPF for detecting vulnerable function calls in real-time.

## Project Overview

This project aims to create an open-source runtime SCA solution that can:
1. Ingest vulnerability data from OSV
2. Process and store function-level vulnerability information
3. Use eBPF to monitor running applications for vulnerable function calls
4. Provide real-time alerts when vulnerable functions are detected

## Current Implementation

### Database Layer (`internal/database/`)

The database layer manages our PostgreSQL schema and connections.

#### Schema

```sql
-- Main vulnerability information
vulnerabilities
- id (TEXT PRIMARY KEY)
- ecosystem (TEXT)
- package (TEXT)
- summary (TEXT)
- details (TEXT)
- has_function_data (BOOLEAN)
- raw_data (JSONB)

-- Version ranges affected by vulnerabilities
affected_versions
- vuln_id (TEXT REFERENCES vulnerabilities)
- version_range (TEXT)
- fixed_version (TEXT)
- package_path (TEXT)

-- Specific vulnerable functions
vulnerable_functions
- vuln_id (TEXT REFERENCES vulnerabilities)
- package_path (TEXT)
- function_name (TEXT)
- source_type (TEXT)
- verified (BOOLEAN)

-- Queue for vulnerabilities needing analysis
analysis_queue
- vuln_id (TEXT REFERENCES vulnerabilities)
- priority (INTEGER)
- attempts (INTEGER)
- last_attempt (TIMESTAMP)
- error_log (TEXT)
```

### OSV Processing (`internal/osv/`)

The OSV processing layer handles ingestion and processing of vulnerability data.

#### Components

- `models/types.go`: Go structs matching OSV JSON format
- `loader.go`: Processes OSV files into database records

#### Data Flow

1. Read OSV JSON files from configured path
2. Parse JSON into structured data
3. Extract:
   - Basic vulnerability information
   - Affected version ranges
   - Function-level data (when available)
4. Store processed data in PostgreSQL
5. Queue entries without function data for further analysis

## Version Range Processing

Currently storing version ranges in a parseable format:
```
">= 1.4.0, < 1.8.0"
">= 0, < 1.6.3"
```

These will be used to determine if a running application's version is within a vulnerable range.

## Next Steps

### 1. Runtime Detection
- Implement version range parser
- Create eBPF probes for function monitoring
- Build matching logic for vulnerability detection
- Implement real-time alerting

### 2. LLM Analysis Pipeline
- Process vulnerability descriptions
- Extract function information
- Validate extracted data
- Update vulnerability database

### 3. Performance Optimization
- Optimize database queries
- Implement caching layer
- Batch processing improvements

## Configuration

Required environment variables:
```bash
POSTGRES_HOST
POSTGRES_USERNAME
POSTGRES_PASSWORD
POSTGRES_DATABASE
OSV_DATA_PATH      # Path to OSV JSON files
```

## Development

To bootstrap the database and load initial OSV data:

```bash
go run main.go
```

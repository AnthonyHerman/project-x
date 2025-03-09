package main

import (
	"log"
	
	"github.com/AnthonyHerman/project-x/internal/database"
	"github.com/AnthonyHerman/project-x/internal/osv"
)

func main() {
	DownloadAndBootstrap()
}

// DownloadAndBootstrap initializes the database schema and downloads
// all vulnerability data for in-scope coding ecosystems from OSV
func DownloadAndBootstrap() {
	log.Println("Starting complete database bootstrap with OSV data download")
	
	// Bootstrap the database schema
	if err := database.Bootstrap(); err != nil {
		log.Fatalf("Failed to bootstrap database: %v", err)
	}
	
	// Create database connection
	db, err := database.New()
	if err != nil {
		log.Fatalf("Failed to create database connection: %v", err)
	}
	defer db.Close()
	
	// Download and process OSV data from upstream
	log.Println("Downloading OSV data for all in-scope ecosystems")
	downloader := osv.NewOSVDownloader(db)
	
	if err := downloader.DownloadAndProcessEcosystems(); err != nil {
		log.Fatalf("Failed to download and process OSV data: %v", err)
	}
	
	// Queue vulnerabilities for LLM analysis
	if err := downloader.QueueVulnerabilitiesForAnalysis(); err != nil {
		log.Fatalf("Failed to queue vulnerabilities for analysis: %v", err)
	}
	
	log.Println("Complete database bootstrap with OSV data completed successfully")
}

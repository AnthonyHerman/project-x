package main

import (
	"log"
	"fmt"
	"flag"
	"os"
	
	"github.com/AnthonyHerman/project-x/internal/database"
	"github.com/AnthonyHerman/project-x/internal/osv"
	"github.com/AnthonyHerman/project-x/internal/grabber"
)

func main() {
	bootstrapCmd := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	analyzeCmd := flag.NewFlagSet("analyze", flag.ExitOnError)
	vulnId := analyzeCmd.String("id", "", "Vulnerability ID to analyze")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}	

	switch os.Args[1] {
	case "bootstrap":
		bootstrapCmd.Parse(os.Args[2:])
		DownloadAndBootstrap()
	case "analyze":
		analyzeCmd.Parse(os.Args[2:])
		if *vulnId == "" {
			fmt.Println("Error: --id is required")
			analyzeCmd.PrintDefaults()
			os.Exit(1)
		}
		RunGrabAndAnalyze(*vulnId)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: project-x <command> [options]")
	fmt.Println("Commands:")
	fmt.Println("  bootstrap - Bootstrap the database with OSV data")
	fmt.Println("  analyze   - Analyze a vulnerability")
}

func RunGrabAndAnalyze(vulnID string) {
	log.Printf("Starting grab and analyze for vulnerability: %s", vulnID)
	
	// Create database connection
	db, err := database.New()
	if err != nil {
		log.Fatalf("Failed to create database connection: %v", err)
	}
	defer db.Close()
	
	// Check if the vulnerability exists
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM vulnerabilities WHERE id = $1)", vulnID).Scan(&exists)
	if err != nil {
		log.Fatalf("Database error: %v", err)
	}
	
	if !exists {
		log.Fatalf("Vulnerability with ID %s not found in database", vulnID)
	}
	
	// Create repository grabber
	repoGrabber := grabber.NewRepositoryGrabber(db)
	defer repoGrabber.Cleanup() // Clean up when done
	
	// Clone the repository
	log.Printf("Cloning repository for vulnerability: %s", vulnID)
	repoPath, err := repoGrabber.CloneRepositoryForVuln(vulnID)
	if err != nil {
		log.Fatalf("Failed to clone repository: %v", err)
	}
	
	log.Printf("Successfully cloned repository to: %s", repoPath)
	
	// TODO: Add code to analyze the repository with LLM here
	log.Printf("Analysis of repository not yet implemented")
	
	// For now, just log the success
	log.Printf("Grab and analyze completed for vulnerability: %s", vulnID)
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

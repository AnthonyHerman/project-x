package main

import (
	"log"
	"os"

	"github.com/AnthonyHerman/project-x/internal/database"
	"github.com/AnthonyHerman/project-x/internal/osv"
)

func main() {
	if err := database.Bootstrap(); err != nil {
		log.Fatalf("Failed to bootstrap database: %v", err)
	}
	
	db, err := database.New()
	if err != nil {
		log.Fatalf("Failed to create database connection: %v", err)
	}
	defer db.Close()

	loader := osv.NewLoader(db)
	if err := loader.LoadFromPath(os.Getenv("OSV_DATA_PATH")); err != nil {
		log.Fatalf("Failed to load OSV data: %v", err)
	}
}

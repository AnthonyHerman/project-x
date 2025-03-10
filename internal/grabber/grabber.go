// internal/grabber/grabber.go
package grabber

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AnthonyHerman/project-x/internal/database"
)

// RepositoryGrabber handles cloning repositories related to vulnerabilities
type RepositoryGrabber struct {
	db          *database.DB
	cloneDir    string
	maxAttempts int
}

// NewRepositoryGrabber creates a new repository grabber
func NewRepositoryGrabber(db *database.DB) *RepositoryGrabber {
	// Create a temporary directory with a project-specific prefix
	baseDir, err := ioutil.TempDir("", "vuln-repos-")
	if err != nil {
		log.Printf("Warning: Failed to create custom temp directory: %v, using system temp", err)
		baseDir = os.TempDir()
	}

	return &RepositoryGrabber{
		db:          db,
		cloneDir:    baseDir,
		maxAttempts: 3,
	}
}

// CloneRepositoryForVuln clones the repository associated with a vulnerability
func (g *RepositoryGrabber) CloneRepositoryForVuln(vulnID string) (string, error) {
	// Get vulnerability data
	var rawData []byte
	var repoURL string
	var packageName string
	var ecosystem string

	err := g.db.QueryRow(`
		SELECT raw_data, package, ecosystem
		FROM vulnerabilities
		WHERE id = $1
	`, vulnID).Scan(&rawData, &packageName, &ecosystem)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve vulnerability data: %w", err)
	}

	// Parse raw data to extract repository URLs
	repoURL, err = g.extractRepositoryURL(rawData, packageName, ecosystem)
	if err != nil {
		return "", fmt.Errorf("failed to extract repository URL: %w", err)
	}

	if repoURL == "" {
		return "", fmt.Errorf("no repository URL found for vulnerability %s", vulnID)
	}

	// Create a directory for this specific vulnerability
	repoDir := filepath.Join(g.cloneDir, vulnID)
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory for repository: %w", err)
	}

	// Clone the repository
	log.Printf("Cloning repository %s for vulnerability %s to %s", repoURL, vulnID, repoDir)
	if err := g.cloneRepo(repoURL, repoDir); err != nil {
		return "", fmt.Errorf("failed to clone repository: %w", err)
	}

	return repoDir, nil
}

// extractRepositoryURL tries to extract the repository URL from the vulnerability data
func (g *RepositoryGrabber) extractRepositoryURL(rawData []byte, packageName, ecosystem string) (string, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return "", fmt.Errorf("failed to parse vulnerability data: %w", err)
	}

	log.Printf("Extracting repository URL for %s/%s", ecosystem, packageName)

	// Look specifically for PACKAGE type references first - these are the most authoritative
	if references, ok := data["references"].([]interface{}); ok {
		for _, ref := range references {
			if refMap, ok := ref.(map[string]interface{}); ok {
				url, urlOk := refMap["url"].(string)
				refType, typeOk := refMap["type"].(string)
				
				if urlOk && typeOk && refType == "PACKAGE" {
					log.Printf("Found authoritative PACKAGE reference URL: %s", url)
					return url, nil
				}
			}
		}
		
		// Second pass for GitHub repositories that aren't advisories
		for _, ref := range references {
			if refMap, ok := ref.(map[string]interface{}); ok {
				url, ok := refMap["url"].(string)
				if !ok {
					continue
				}

				// Check if it's a GitHub repository but not an advisory
				if strings.Contains(url, "github.com") && 
				   !strings.Contains(url, "advisories") && 
				   !strings.Contains(url, "security") &&
				   !strings.Contains(url, "advisory") {
					log.Printf("Found GitHub repository URL: %s", url)
					return url, nil
				}
			}
		}
	}

	// If we can't find it in references, use the resolver to look up the package
	resolver := NewPackageResolver()
	repoURL, err := resolver.ResolveRepositoryURL(packageName, ecosystem)
	if err != nil {
		log.Printf("Warning: Failed to resolve repository URL for %s/%s: %v", ecosystem, packageName, err)
		fallbackURL := g.guessRepositoryURL(packageName, ecosystem)
		log.Printf("Falling back to best guess URL: %s", fallbackURL)
		return fallbackURL, nil
	}
	
	log.Printf("Resolved repository URL via package registry: %s", repoURL)
	return repoURL, nil
}

// guessRepositoryURL attempts to construct a repository URL based on package info
// This is a fallback method when the package resolver fails
func (g *RepositoryGrabber) guessRepositoryURL(packageName, ecosystem string) string {
	// For Mezzanine specifically, we know the URL
	if packageName == "mezzanine" && ecosystem == "PyPI" {
		return "https://github.com/stephenmcd/mezzanine"
	}
	
	switch ecosystem {
	case "PyPI":
		return fmt.Sprintf("https://github.com/search?q=%s+language:python", packageName)
	case "npm":
		return fmt.Sprintf("https://github.com/search?q=%s+language:javascript", packageName)
	case "Go":
		return fmt.Sprintf("https://github.com/search?q=%s+language:go", packageName)
	case "Maven":
		return fmt.Sprintf("https://github.com/search?q=%s+language:java", packageName)
	case "RubyGems":
		return fmt.Sprintf("https://github.com/search?q=%s+language:ruby", packageName)
	case "crates.io":
		return fmt.Sprintf("https://github.com/search?q=%s+language:rust", packageName)
	case "Hex":
		return fmt.Sprintf("https://github.com/search?q=%s+language:elixir", packageName)
	case "NuGet":
		return fmt.Sprintf("https://github.com/search?q=%s+language:csharp", packageName)
	case "Packagist":
		return fmt.Sprintf("https://github.com/search?q=%s+language:php", packageName)
	case "Pub":
		return fmt.Sprintf("https://github.com/search?q=%s+language:dart", packageName)
	case "Haskell":
		return fmt.Sprintf("https://github.com/search?q=%s+language:haskell", packageName)
	default:
		return fmt.Sprintf("https://github.com/search?q=%s", packageName)
	}
}

// cloneRepo clones a git repository to the specified directory
func (g *RepositoryGrabber) cloneRepo(url, dir string) error {
	for attempt := 1; attempt <= g.maxAttempts; attempt++ {
		cmd := exec.Command("git", "clone", "--depth", "1", url, dir)
		output, err := cmd.CombinedOutput()
		
		if err == nil {
			log.Printf("Successfully cloned repository: %s", url)
			return nil
		}
		
		log.Printf("Attempt %d: Failed to clone repository: %s, Error: %v, Output: %s", 
			attempt, url, err, string(output))
		
		// Clean up failed clone attempt
		os.RemoveAll(dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to recreate directory after failed clone: %w", err)
		}
		
		// Wait before retrying
		if attempt < g.maxAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	
	return fmt.Errorf("failed to clone repository after %d attempts", g.maxAttempts)
}

// GetRepositoryPath returns the path where a repository for a vulnerability should be
func (g *RepositoryGrabber) GetRepositoryPath(vulnID string) string {
	return filepath.Join(g.cloneDir, vulnID)
}

// Cleanup removes downloaded repositories
func (g *RepositoryGrabber) Cleanup() error {
	return os.RemoveAll(g.cloneDir)
}

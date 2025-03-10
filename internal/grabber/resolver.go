// internal/grabber/resolver.go
package grabber

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// PackageResolver helps resolve package names to repository URLs
type PackageResolver struct {
	httpClient *http.Client
}

// NewPackageResolver creates a new package resolver
func NewPackageResolver() *PackageResolver {
	return &PackageResolver{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ResolveRepositoryURL attempts to find the repository URL for a package
func (r *PackageResolver) ResolveRepositoryURL(packageName, ecosystem string) (string, error) {
	switch ecosystem {
	case "PyPI":
		return r.resolvePyPIPackage(packageName)
	case "npm":
		return r.resolveNpmPackage(packageName)
	case "Go":
		return r.resolveGoPackage(packageName)
	case "RubyGems":
		return r.resolveRubyGemsPackage(packageName)
	case "crates.io":
		return r.resolveCratesPackage(packageName)
	case "Maven":
		return r.resolveMavenPackage(packageName)
	default:
		log.Printf("No specific resolver for ecosystem %s, falling back to GitHub search", ecosystem)
		return fmt.Sprintf("https://github.com/search?q=%s", packageName), nil
	}
}

// resolvePyPIPackage resolves a PyPI package to its repository URL
func (r *PackageResolver) resolvePyPIPackage(packageName string) (string, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", packageName)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to query PyPI API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PyPI API returned non-OK status: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read PyPI API response: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("failed to parse PyPI API response: %w", err)
	}

	info, ok := data["info"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected PyPI API response format")
	}

	// Try project_urls first
	if projectURLs, ok := info["project_urls"].(map[string]interface{}); ok {
		for key, url := range projectURLs {
			if strings.Contains(strings.ToLower(key), "source") || 
			   strings.Contains(strings.ToLower(key), "repository") || 
			   strings.Contains(strings.ToLower(key), "github") {
				if repoURL, ok := url.(string); ok && repoURL != "" {
					return repoURL, nil
				}
			}
		}
	}

	// Try home_page
	if homePage, ok := info["home_page"].(string); ok && homePage != "" {
		if strings.Contains(homePage, "github.com") || 
		   strings.Contains(homePage, "gitlab.com") || 
		   strings.Contains(homePage, "bitbucket.org") {
			return homePage, nil
		}
	}

	// Fall back to GitHub search
	return fmt.Sprintf("https://github.com/search?q=%s", packageName), nil
}

// resolveNpmPackage resolves an npm package to its repository URL
func (r *PackageResolver) resolveNpmPackage(packageName string) (string, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to query npm registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("npm registry returned non-OK status: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read npm registry response: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("failed to parse npm registry response: %w", err)
	}

	// Try repository field
	if repo, ok := data["repository"].(map[string]interface{}); ok {
		if url, ok := repo["url"].(string); ok && url != "" {
			// Clean up the URL if it's a git URL
			url = strings.TrimPrefix(url, "git+")
			url = strings.TrimSuffix(url, ".git")
			if strings.HasPrefix(url, "git://") {
				url = "https://" + strings.TrimPrefix(url, "git://")
			}
			return url, nil
		}
	}

	// Try homepage
	if homepage, ok := data["homepage"].(string); ok && homepage != "" {
		if strings.Contains(homepage, "github.com") || 
		   strings.Contains(homepage, "gitlab.com") || 
		   strings.Contains(homepage, "bitbucket.org") {
			return homepage, nil
		}
	}

	// Fall back to GitHub search
	return fmt.Sprintf("https://github.com/search?q=%s", packageName), nil
}

// resolveGoPackage resolves a Go package to its repository URL
func (r *PackageResolver) resolveGoPackage(packageName string) (string, error) {
	// For Go packages, the package name is often the repository URL
	// Strip any version suffix
	if strings.Contains(packageName, "@") {
		packageName = strings.Split(packageName, "@")[0]
	}

	// Add https:// prefix if not present
	if !strings.HasPrefix(packageName, "http") {
		packageName = "https://" + packageName
	}

	return packageName, nil
}

// resolveRubyGemsPackage resolves a RubyGems package to its repository URL
func (r *PackageResolver) resolveRubyGemsPackage(packageName string) (string, error) {
	url := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", packageName)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to query RubyGems API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("RubyGems API returned non-OK status: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read RubyGems API response: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("failed to parse RubyGems API response: %w", err)
	}

	// Try source_code_uri
	if sourceCodeURI, ok := data["source_code_uri"].(string); ok && sourceCodeURI != "" {
		return sourceCodeURI, nil
	}

	// Try homepage_uri
	if homepageURI, ok := data["homepage_uri"].(string); ok && homepageURI != "" {
		if strings.Contains(homepageURI, "github.com") || 
		   strings.Contains(homepageURI, "gitlab.com") || 
		   strings.Contains(homepageURI, "bitbucket.org") {
			return homepageURI, nil
		}
	}

	// Fall back to GitHub search
	return fmt.Sprintf("https://github.com/search?q=%s", packageName), nil
}

// resolveCratesPackage resolves a Rust crate to its repository URL
func (r *PackageResolver) resolveCratesPackage(packageName string) (string, error) {
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s", packageName)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to query crates.io API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("crates.io API returned non-OK status: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read crates.io API response: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("failed to parse crates.io API response: %w", err)
	}

	if crateData, ok := data["crate"].(map[string]interface{}); ok {
		// Try repository URL
		if repoURL, ok := crateData["repository"].(string); ok && repoURL != "" {
			return repoURL, nil
		}

		// Try homepage
		if homepage, ok := crateData["homepage"].(string); ok && homepage != "" {
			if strings.Contains(homepage, "github.com") || 
			   strings.Contains(homepage, "gitlab.com") || 
			   strings.Contains(homepage, "bitbucket.org") {
				return homepage, nil
			}
		}
	}

	// Fall back to GitHub search
	return fmt.Sprintf("https://github.com/search?q=%s", packageName), nil
}

// resolveMavenPackage resolves a Maven package to its repository URL
func (r *PackageResolver) resolveMavenPackage(packageName string) (string, error) {
	// Maven packages are more complex to resolve
	// For now, we'll just search on GitHub
	return fmt.Sprintf("https://github.com/search?q=%s", packageName), nil
}

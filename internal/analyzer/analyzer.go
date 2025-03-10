// internal/analyzer/analyzer.go
package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	
	"github.com/AnthonyHerman/project-x/internal/database"
)

// Supported file extensions for different ecosystems
var ecosystemExtensions = map[string][]string{
	"PyPI":      {".py"},
	"npm":       {".js", ".ts", ".jsx", ".tsx"},
	"Go":        {".go"},
	"Maven":     {".java"},
	"RubyGems":  {".rb"},
	"crates.io": {".rs"},
	"Hex":       {".ex", ".exs"},
	"NuGet":     {".cs", ".vb"},
	"Packagist": {".php"},
	"Pub":       {".dart"},
	"Haskell":   {".hs"},
}

// CodeAnalyzer handles LLM-based analysis of code repositories
type CodeAnalyzer struct {
	db            *database.DB
	llmServerURL  string
	maxCodeSize   int    // Maximum size of code per request in bytes
	maxFiles      int    // Maximum number of files to analyze per vulnerability
	confidence    float64 // Minimum confidence threshold for functions
	requestTimeout time.Duration // Timeout for LLM requests
}

// NewCodeAnalyzer creates a new code analyzer
func NewCodeAnalyzer(db *database.DB) *CodeAnalyzer {
	llmServerURL := os.Getenv("LLM_SERVER_URL")
	if llmServerURL == "" {
		llmServerURL = "http://127.0.0.1:8080/completion" // Default
	}
	
	// Read timeout from environment or use a generous default for local LLMs
	timeoutStr := os.Getenv("LLM_REQUEST_TIMEOUT")
	timeout := 5 * time.Minute // Default to 5 minutes for local LLMs
	if timeoutStr != "" {
		if parsedTimeout, err := time.ParseDuration(timeoutStr); err == nil {
			timeout = parsedTimeout
		}
	}
	
	return &CodeAnalyzer{
		db:             db,
		llmServerURL:   llmServerURL,
		maxCodeSize:    50000,  // 50KB max per request
		maxFiles:       50,     // Analyze at most 50 files per vulnerability
		confidence:     0.6,    // 60% minimum confidence
		requestTimeout: timeout,
	}
}

// AnalyzeRepository analyzes a repository for vulnerable functions
func (a *CodeAnalyzer) AnalyzeRepository(vulnID, repoPath string) error {
	log.Printf("Analyzing repository for vulnerability %s at %s", vulnID, repoPath)
	
	// Get vulnerability details
	var summary, details string
	var ecosystem, packageName string
	var rawData []byte
	
	err := a.db.QueryRow(`
		SELECT summary, details, ecosystem, package, raw_data
		FROM vulnerabilities
		WHERE id = $1
	`, vulnID).Scan(&summary, &details, &ecosystem, &packageName, &rawData)
	if err != nil {
		return fmt.Errorf("failed to retrieve vulnerability details: %w", err)
	}
	
	// Parse vulnerability data
	var vulnData map[string]interface{}
	if err := json.Unmarshal(rawData, &vulnData); err != nil {
		return fmt.Errorf("failed to parse vulnerability data: %w", err)
	}
	
	// Get relevant files for the ecosystem
	files, err := a.findRelevantFiles(repoPath, ecosystem)
	if err != nil {
		return fmt.Errorf("failed to find relevant files: %w", err)
	}
	
	if len(files) == 0 {
		return fmt.Errorf("no relevant files found for ecosystem %s", ecosystem)
	}
	
	log.Printf("Found %d relevant files for analysis", len(files))
	
	// Create vulnerability context
	vulnContext := a.createVulnerabilityContext(vulnID, summary, details, ecosystem, packageName, vulnData)
	
	// Analyze by file groups to manage context size
	var identifiedFunctions []IdentifiedFunction
	
	// First pass: look for high-level patterns across critical files
	criticalFiles := a.identifyCriticalFiles(files, ecosystem, vulnContext)
	if len(criticalFiles) > 0 {
		log.Printf("First pass analysis with %d critical files", len(criticalFiles))
		functions, err := a.analyzeFileGroup(criticalFiles, vulnContext)
		if err != nil {
			log.Printf("Warning: First pass analysis failed: %v", err)
		} else {
			identifiedFunctions = append(identifiedFunctions, functions...)
		}
	}
	
	// Second pass: analyze files in smaller groups
	fileGroups := a.groupFiles(files, a.maxCodeSize)
	for i, group := range fileGroups {
		log.Printf("Analyzing file group %d of %d (%d files)", i+1, len(fileGroups), len(group))
		functions, err := a.analyzeFileGroup(group, vulnContext)
		if err != nil {
			log.Printf("Warning: Failed to analyze file group %d: %v", i+1, err)
			continue
		}
		identifiedFunctions = append(identifiedFunctions, functions...)
	}
	
	// Filter and save the results
	finalFunctions := a.consolidateResults(identifiedFunctions)
	return a.saveFunctions(vulnID, finalFunctions)
}

// findRelevantFiles finds files in the repository that are relevant for the ecosystem
func (a *CodeAnalyzer) findRelevantFiles(repoPath, ecosystem string) ([]string, error) {
	extensions, ok := ecosystemExtensions[ecosystem]
	if !ok {
		return nil, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
	
	var relevantFiles []string
	limit := a.maxFiles // Limit the number of files to analyze
	
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip directories, hidden files, and test files (for initial analysis)
		if info.IsDir() || strings.HasPrefix(info.Name(), ".") {
			return nil
		}
		
		// Skip test directories (common patterns)
		if strings.Contains(path, "/test/") || 
		   strings.Contains(path, "/tests/") || 
		   strings.Contains(path, "/testing/") {
			return nil
		}
		
		// Skip test files themselves (for first-pass analysis)
		if strings.HasSuffix(info.Name(), "_test.go") || 
		   strings.HasSuffix(info.Name(), "_test.py") || 
		   strings.HasSuffix(info.Name(), ".test.js") || 
		   strings.HasPrefix(info.Name(), "test_") {
			return nil
		}
		
		// Check if the file has a relevant extension
		for _, ext := range extensions {
			if strings.HasSuffix(path, ext) {
				relevantFiles = append(relevantFiles, path)
				if len(relevantFiles) >= limit {
					return filepath.SkipAll
				}
				break
			}
		}
		
		return nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to walk repository: %w", err)
	}
	
	return relevantFiles, nil
}

// identifyCriticalFiles identifies files that are likely to be relevant to the vulnerability
func (a *CodeAnalyzer) identifyCriticalFiles(files []string, ecosystem string, vulnContext string) []string {
	var criticalFiles []string
	
	// Look for files with patterns related to vulnerability
	keywordsLower := a.extractKeywords(vulnContext)
	
	// Generic critical file identification based on extracted keywords
	for _, file := range files {
		fileLower := strings.ToLower(file)
		
		for _, keyword := range keywordsLower {
			if strings.Contains(fileLower, keyword) {
				criticalFiles = append(criticalFiles, file)
				break
			}
		}
	}
	
	// Limit the number of critical files
	if len(criticalFiles) > 10 {
		criticalFiles = criticalFiles[:10]
	}
	
	return criticalFiles
}

// extractKeywords extracts keywords from vulnerability context for searching
func (a *CodeAnalyzer) extractKeywords(vulnContext string) []string {
	// Convert to lowercase for case-insensitive matching
	contextLower := strings.ToLower(vulnContext)
	
	// Common security-related terms to look for in filenames
	securityTerms := []string{
		"auth", "access", "control", "permission", "security", 
		"header", "http", "request", "validate", "check",
		"verify", "token", "session", "bypass", "exploit", 
		"vulnerability", "risk", "mitigation", "protection",
		"input", "sanitize", "filter", "escape", "encode",
		"host", "domain", "url", "uri", "path", "route",
		"api", "view", "template", "render", "handler",
		"admin", "user", "account", "login", "auth",
		"middleware", "sql", "query", "database", "cache",
		"config", "settings", "utils", "helpers", "core",
		"parse", "serialize", "deserialize", "json", "xml",
	}
	
	// Extract likely meaningful terms from the vulnerability context
	var keywords []string
	
	// First pass: add security terms found in the context
	for _, term := range securityTerms {
		if strings.Contains(contextLower, term) {
			keywords = append(keywords, term)
		}
	}
	
	// Second pass: extract potential component names
	// Look for words that might be code component names
	words := strings.Fields(contextLower)
	for _, word := range words {
		// Clean the word
		word = strings.Trim(word, ",.()[]{}\"':;!?")
		
		// Ignore common words, focus on likely component names
		if len(word) > 3 && !isCommonWord(word) {
			keywords = append(keywords, word)
		}
	}
	
	return keywords
}

// isCommonWord checks if a word is a common English word not likely to be a code component
func isCommonWord(word string) bool {
	commonWords := map[string]bool{
		"the": true, "and": true, "that": true, "have": true, "for": true,
		"not": true, "with": true, "this": true, "from": true, "they": true,
		"will": true, "would": true, "there": true, "their": true, "what": true,
		"about": true, "which": true, "when": true, "make": true, "like": true,
		"time": true, "just": true, "know": true, "people": true, "year": true,
		"your": true, "some": true, "could": true, "them": true, "other": true,
		"than": true, "then": true, "into": true, "more": true, "these": true,
		"also": true, "only": true, "issue": true, "via": true,
		"attackers": true, "bypass": true, "using": true,
	}
	
	return commonWords[word]
}

// createVulnerabilityContext creates a context description for the LLM
func (a *CodeAnalyzer) createVulnerabilityContext(vulnID, summary, details, ecosystem, packageName string, vulnData map[string]interface{}) string {
	context := fmt.Sprintf(`
VULNERABILITY ID: %s
PACKAGE: %s (Ecosystem: %s)
SUMMARY: %s
DETAILS: %s
`, vulnID, packageName, ecosystem, summary, details)
	
	// Add affected versions if available
	if affected, ok := vulnData["affected"].([]interface{}); ok && len(affected) > 0 {
		if affectedObj, ok := affected[0].(map[string]interface{}); ok {
			if versions, ok := affectedObj["versions"].([]interface{}); ok && len(versions) > 0 {
				context += "AFFECTED VERSIONS: "
				for i, v := range versions {
					if i > 0 {
						context += ", "
					}
					if i >= 5 {
						context += "... (truncated)"
						break
					}
					context += fmt.Sprintf("%v", v)
				}
				context += "\n"
			}
		}
	}
	
	// Extract and add vulnerability type if possible
	vulnType := inferVulnerabilityType(summary, details)
	if vulnType != "" {
		context += fmt.Sprintf("VULNERABILITY TYPE: %s\n", vulnType)
	}
	
	// Add CWE IDs if available
	if dbSpecific, ok := vulnData["database_specific"].(map[string]interface{}); ok {
		if cweIDs, ok := dbSpecific["cwe_ids"].([]interface{}); ok && len(cweIDs) > 0 {
			context += "CWE IDs: "
			for i, cwe := range cweIDs {
				if i > 0 {
					context += ", "
				}
				context += fmt.Sprintf("%v", cwe)
			}
			context += "\n"
		}
	}
	
	// Add references if available
	if refs, ok := vulnData["references"].([]interface{}); ok && len(refs) > 0 {
		context += "REFERENCES:\n"
		count := 0
		for _, r := range refs {
			if count >= 3 { // Limit to 3 references
				break
			}
			if refMap, ok := r.(map[string]interface{}); ok {
				if url, ok := refMap["url"].(string); ok {
					refType := ""
					if t, ok := refMap["type"].(string); ok {
						refType = t
					}
					context += fmt.Sprintf("- %s (%s)\n", url, refType)
					count++
				}
			}
		}
	}
	
	return context
}

// inferVulnerabilityType attempts to infer the vulnerability type from the description
func inferVulnerabilityType(summary, details string) string {
	combined := strings.ToLower(summary + " " + details)
	
	// Check for common vulnerability types
	if strings.Contains(combined, "sql injection") || strings.Contains(combined, "sqli") {
		return "SQL Injection"
	} else if strings.Contains(combined, "xss") || strings.Contains(combined, "cross-site scripting") {
		return "Cross-Site Scripting (XSS)"
	} else if strings.Contains(combined, "csrf") || strings.Contains(combined, "cross-site request forgery") {
		return "Cross-Site Request Forgery (CSRF)"
	} else if strings.Contains(combined, "path traversal") || strings.Contains(combined, "directory traversal") {
		return "Path Traversal"
	} else if strings.Contains(combined, "command injection") || strings.Contains(combined, "os command") {
		return "Command Injection"
	} else if strings.Contains(combined, "buffer overflow") || strings.Contains(combined, "buffer over-read") {
		return "Buffer Overflow"
	} else if strings.Contains(combined, "deserialization") {
		return "Insecure Deserialization"
	} else if strings.Contains(combined, "ssrf") || strings.Contains(combined, "server-side request forgery") {
		return "Server-Side Request Forgery (SSRF)"
	} else if strings.Contains(combined, "header") || strings.Contains(combined, "http header") {
		return "HTTP Header Manipulation"
	} else if strings.Contains(combined, "access control") || strings.Contains(combined, "authorization") {
		return "Access Control Vulnerability"
	} else if strings.Contains(combined, "race condition") {
		return "Race Condition"
	} else if strings.Contains(combined, "information disclosure") || strings.Contains(combined, "information leak") {
		return "Information Disclosure"
	} else if strings.Contains(combined, "integer overflow") || strings.Contains(combined, "integer underflow") {
		return "Integer Overflow/Underflow"
	} else if strings.Contains(combined, "denial of service") || strings.Contains(combined, "dos") {
		return "Denial of Service (DoS)"
	} else if strings.Contains(combined, "xml") || strings.Contains(combined, "xxe") {
		return "XML External Entity (XXE)"
	} else if strings.Contains(combined, "open redirect") {
		return "Open Redirect"
	}
	
	return "" // Unknown or couldn't infer
}

// groupFiles groups files to fit within the maximum context size
func (a *CodeAnalyzer) groupFiles(files []string, maxSize int) [][]string {
	var groups [][]string
	var currentGroup []string
	var currentSize int
	
	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			log.Printf("Warning: Failed to get file size for %s: %v", file, err)
			continue
		}
		
		fileSize := int(fileInfo.Size())
		
		// If the file itself is too large, skip it
		if fileSize > maxSize {
			log.Printf("Warning: File %s is too large (%d bytes), skipping", file, fileSize)
			continue
		}
		
		// If adding this file would exceed the limit, start a new group
		if currentSize+fileSize > maxSize && len(currentGroup) > 0 {
			groups = append(groups, currentGroup)
			currentGroup = []string{file}
			currentSize = fileSize
		} else {
			currentGroup = append(currentGroup, file)
			currentSize += fileSize
		}
	}
	
	// Add the last group if it's not empty
	if len(currentGroup) > 0 {
		groups = append(groups, currentGroup)
	}
	
	return groups
}

// IdentifiedFunction represents a function identified by the LLM
type IdentifiedFunction struct {
	PackagePath   string  `json:"package_path"`
	FunctionName  string  `json:"function_name"`
	Confidence    float64 `json:"confidence"`
	Reasoning     string  `json:"reasoning"`
	FileLocation  string  `json:"file_location,omitempty"` // For internal tracking
}

// LLMResponse represents the response from the LLM
type LLMResponse struct {
	Choices []struct {
		Text string `json:"text"`
	} `json:"choices"`
}

// analyzeFileGroup analyzes a group of files with the LLM
func (a *CodeAnalyzer) analyzeFileGroup(files []string, vulnContext string) ([]IdentifiedFunction, error) {
	// Prepare the files content
	var fileContents string
	for _, file := range files {
		content, err := ioutil.ReadFile(file)
		if err != nil {
			log.Printf("Warning: Failed to read file %s: %v", file, err)
			continue
		}
		
		// Calculate relative path from repository root for better context
		relPath := filepath.Base(file)
		fileContents += fmt.Sprintf("\n\n--- FILE: %s ---\n%s\n", relPath, content)
	}
	
	// If the content is too large, truncate it
	if len(fileContents) > a.maxCodeSize {
		log.Printf("Warning: File content exceeds maximum size, truncating to %d bytes", a.maxCodeSize)
		fileContents = fileContents[:a.maxCodeSize] + "\n... (content truncated due to size limits)"
	}
	
	// Create the prompt for the LLM
	prompt := a.createAnalysisPrompt(vulnContext, fileContents)
	
	// Send the request to the LLM, with retry
	var functions []IdentifiedFunction
	var err error
	
	// Try up to 3 times with increasing timeouts
	for attempt := 1; attempt <= 3; attempt++ {
		log.Printf("LLM analysis attempt %d of 3", attempt)
		
		functions, err = a.queryLLM(prompt)
		if err == nil {
			break // Success
		}
		
		// Check if it's a timeout error
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			log.Printf("Attempt %d timed out, retrying with longer timeout", attempt)
			// Increase timeout for next attempt
			a.requestTimeout = a.requestTimeout * 2
			continue
		}
		
		// For other errors, just return the error
		return nil, err
	}
	
	if err != nil {
		return nil, fmt.Errorf("all LLM analysis attempts failed: %w", err)
	}
	
	// Add file location for internal tracking
	for i := range functions {
		for _, file := range files {
			if strings.Contains(file, functions[i].PackagePath) {
				functions[i].FileLocation = file
				break
			}
		}
	}
	
	return functions, nil
}

// createAnalysisPrompt creates the prompt for the LLM
func (a *CodeAnalyzer) createAnalysisPrompt(vulnContext, fileContents string) string {
	prompt := `You are a security code analyst tasked with identifying vulnerable functions in source code. You will be given:
1. A description of a security vulnerability
2. Source code files from a software package

Your task is to analyze the code and identify specific functions that are most likely responsible for this vulnerability. Think step by step about how the vulnerability described could manifest in code.

VULNERABILITY INFORMATION:
` + vulnContext + `

SOURCE CODE FILES:
The files below contain code from the vulnerable package. Analyze them carefully to identify functions that might contain the vulnerability.

` + fileContents + `

ANALYSIS INSTRUCTIONS:
1. First, understand the vulnerability type and attack vector from the description
2. Search for code patterns that could enable this vulnerability
3. Look for security-sensitive operations related to the vulnerability type
4. Identify functions that process or handle the attack vector
5. Evaluate which functions lack proper validation or security controls

Based on your analysis, identify the functions that are most likely responsible for this vulnerability.

For each function you identify, provide:
1. The package path (module or namespace)
2. The function name (or method name)
3. A confidence score between 0.0 and 1.0
4. Detailed reasoning explaining why this function is likely vulnerable

Format your response as a JSON array of objects with these fields:
[
  {
    "package_path": "example.module.component",
    "function_name": "process_data",
    "confidence": 0.85,
    "reasoning": "This function directly handles untrusted input and lacks proper validation before using it in security-sensitive operations."
  }
]

Only respond with the properly formatted JSON array, no additional text or explanations.`

	return prompt
}

// queryLLM sends a query to the LLM and parses the response
func (a *CodeAnalyzer) queryLLM(prompt string) ([]IdentifiedFunction, error) {
	// Prepare the request
	requestBody, err := json.Marshal(map[string]interface{}{
		"prompt": prompt,
		"temperature": 0.1,
		"max_tokens": 1000,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: a.requestTimeout,
	}
	
	log.Printf("Sending request to LLM with timeout of %v", a.requestTimeout)
	
	// Send the request
	resp, err := client.Post(a.llmServerURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		if os.IsTimeout(err) || strings.Contains(err.Error(), "timeout") {
			return nil, fmt.Errorf("LLM request timed out after %v: %w", a.requestTimeout, err)
		}
		return nil, fmt.Errorf("failed to send request to LLM: %w", err)
	}
	defer resp.Body.Close()
	
	// Check the response status
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("LLM returned non-OK status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	
	// Parse the response
	var llmResponse LLMResponse
	if err := json.NewDecoder(resp.Body).Decode(&llmResponse); err != nil {
		return nil, fmt.Errorf("failed to decode LLM response: %w", err)
	}
	
	if len(llmResponse.Choices) == 0 {
		return nil, fmt.Errorf("empty response from LLM")
	}
	
	// Extract the JSON from the response
	responseText := llmResponse.Choices[0].Text
	responseText = strings.TrimSpace(responseText)
	
	// Sometimes LLMs might add markdown code block markers
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimPrefix(responseText, "```")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)
	
	// Parse the JSON
	var functions []IdentifiedFunction
	if err := json.Unmarshal([]byte(responseText), &functions); err != nil {
		// If JSON parsing fails, try to salvage any JSON-looking parts
		if jsonStart := strings.Index(responseText, "["); jsonStart >= 0 {
			if jsonEnd := strings.LastIndex(responseText, "]"); jsonEnd > jsonStart {
				potentialJSON := responseText[jsonStart : jsonEnd+1]
				if err := json.Unmarshal([]byte(potentialJSON), &functions); err == nil {
					log.Printf("Warning: Had to extract JSON from malformed response")
					return functions, nil
				}
			}
		}
		
		return nil, fmt.Errorf("failed to parse LLM response as JSON: %w\nResponse text: %s", err, responseText)
	}
	
	return functions, nil
}

// consolidateResults filters and merges the results
func (a *CodeAnalyzer) consolidateResults(functions []IdentifiedFunction) []IdentifiedFunction {
	if len(functions) == 0 {
		return functions
	}
	
	// Map to deduplicate functions by package path and name
	funcMap := make(map[string]IdentifiedFunction)
	
	for _, fn := range functions {
		// Skip low confidence results
		if fn.Confidence < a.confidence {
			continue
		}
		
		key := fn.PackagePath + "." + fn.FunctionName
		existing, exists := funcMap[key]
		
		if !exists || fn.Confidence > existing.Confidence {
			funcMap[key] = fn
		}
	}
	
	// Convert back to slice, sorted by confidence
	var result []IdentifiedFunction
	for _, fn := range funcMap {
		result = append(result, fn)
	}
	
	// Sort by confidence (highest first)
	// Note: using a simple bubble sort here for clarity
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Confidence < result[j].Confidence {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	
	return result
}

// saveFunctions saves the identified functions to the database
func (a *CodeAnalyzer) saveFunctions(vulnID string, functions []IdentifiedFunction) error {
	if len(functions) == 0 {
		log.Printf("No functions identified for vulnerability %s", vulnID)
		return nil
	}
	
	log.Printf("Saving %d identified functions for vulnerability %s", len(functions), vulnID)
	
	// Start a transaction
	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()
	
	// Update vulnerability record
	_, err = tx.Exec(`
		UPDATE vulnerabilities
		SET has_function_data = true, 
		    needs_analysis = false,
		    last_analyzed = CURRENT_TIMESTAMP
		WHERE id = $1
	`, vulnID)
	if err != nil {
		return fmt.Errorf("failed to update vulnerability record: %w", err)
	}
	
	// Update analysis queue
	_, err = tx.Exec(`
		UPDATE analysis_queue
		SET attempts = attempts + 1,
		    last_attempt = CURRENT_TIMESTAMP
		WHERE vuln_id = $1
	`, vulnID)
	if err != nil {
		return fmt.Errorf("failed to update analysis queue: %w", err)
	}
	
	// Insert identified functions
	for _, fn := range functions {
		_, err = tx.Exec(`
			INSERT INTO vulnerable_functions
			(vuln_id, package_path, function_name, source_type, confidence, verified)
			VALUES ($1, $2, $3, 'llm', $4, false)
			ON CONFLICT (vuln_id, package_path, function_name) DO UPDATE SET
				source_type = EXCLUDED.source_type,
				confidence = EXCLUDED.confidence,
				updated_at = CURRENT_TIMESTAMP
		`, vulnID, fn.PackagePath, fn.FunctionName, fn.Confidence)
		
		if err != nil {
			return fmt.Errorf("failed to insert function %s.%s: %w", fn.PackagePath, fn.FunctionName, err)
		}
	}
	
	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	
	log.Printf("Successfully saved %d functions for vulnerability %s", len(functions), vulnID)
	return nil
}

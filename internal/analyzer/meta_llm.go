// internal/analyzer/meta_llm.go
package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// VulnerabilityAnalysis represents the parsed output from the meta-LLM
type VulnerabilityAnalysis struct {
	VulnType                string   `json:"vulnerability_type"`
	AttackVectors           []string `json:"attack_vectors"`
	PotentialVulnerableAreas []string `json:"potentially_vulnerable_areas"`
	RelevantFilePatterns    []string `json:"relevant_file_patterns"`
	KeywordImportance       map[string]float64 `json:"keyword_importance"`
}

// PromptTemplates represents specialized prompts for different analysis scenarios
type PromptTemplates struct {
	MainAnalysisPrompt      string `json:"main_analysis_prompt"`
	FileFilteringPrompt     string `json:"file_filtering_prompt"`
	RequestHandlingPrompt   string `json:"request_handling_prompt"`
	MiddlewarePrompt        string `json:"middleware_prompt"`
	SecurityCheckPrompt     string `json:"security_check_prompt"`
	ResultValidationPrompt  string `json:"result_validation_prompt"`
}

// MetaLLMResponse represents the full response from the meta-LLM
type MetaLLMResponse struct {
	Analysis VulnerabilityAnalysis `json:"analysis"`
	Prompts  PromptTemplates       `json:"prompts"`
}

// generateAnalysisPrompts uses a meta-LLM to generate specialized prompts for analysis
func (a *CodeAnalyzer) generateAnalysisPrompts(vulnID, summary, details, ecosystem, packageName string) (*MetaLLMResponse, error) {
	log.Printf("Generating specialized prompts for vulnerability analysis...")
	
	// Create a prompt for the meta-LLM
	metaPrompt := a.createMetaLLMPrompt(vulnID, summary, details, ecosystem, packageName)
	
	// Query the meta-LLM
	metaLLMResponse, err := a.queryMetaLLM(metaPrompt)
	if err != nil {
		return nil, fmt.Errorf("meta-LLM query failed: %w", err)
	}
	
	log.Printf("Successfully generated specialized analysis prompts")
	return metaLLMResponse, nil
}

// createMetaLLMPrompt creates a prompt for the meta-LLM to analyze
func (a *CodeAnalyzer) createMetaLLMPrompt(vulnID, summary, details, ecosystem, packageName string) string {
	return fmt.Sprintf(`[INST] You are a security expert specializing in vulnerability analysis and prompt engineering. Your task is to analyze a vulnerability description and generate specialized prompts for code analysis.

VULNERABILITY INFORMATION:
ID: %s
Package: %s (Ecosystem: %s)
Summary: %s
Details: %s

Your task is to:
1. Analyze this vulnerability to understand its type, attack vectors, and potential vulnerable code patterns
2. Generate specialized prompts that will help another LLM identify vulnerable functions in source code

Respond with a JSON object containing two main sections:
1. An "analysis" section with your assessment of the vulnerability
2. A "prompts" section with specialized prompts for different analysis scenarios

The analysis should include:
- vulnerability_type: The specific type of vulnerability (e.g., "SQL Injection", "Path Traversal")
- attack_vectors: Key attack vectors or methods of exploitation
- potentially_vulnerable_areas: Areas of code likely to contain the vulnerability
- relevant_file_patterns: File naming patterns that might contain vulnerable code
- keyword_importance: A mapping of keywords to their importance (0.0-1.0) for identifying relevant files

The prompts section should include these template prompts:
- main_analysis_prompt: The primary prompt for analyzing code
- file_filtering_prompt: Prompt for identifying relevant files
- request_handling_prompt: Specialized prompt for analyzing request handling code
- middleware_prompt: Specialized prompt for analyzing middleware components
- security_check_prompt: Specialized prompt for analyzing security verification code
- result_validation_prompt: Prompt for validating and ranking identified functions

Each prompt should be specifically tailored to help identify code related to this exact vulnerability. Be precise and detailed in your prompts to ensure they target the specific vulnerability pattern.

Format your response as a properly formatted JSON object with these fields. [/INST]`, vulnID, packageName, ecosystem, summary, details)
}

// queryMetaLLM sends a query to the meta-LLM and parses the structured response
func (a *CodeAnalyzer) queryMetaLLM(prompt string) (*MetaLLMResponse, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: a.requestTimeout,
	}
	
	// Prepare the request
	requestBody, err := json.Marshal(map[string]interface{}{
		"prompt":       prompt,
		"temperature":  0.2,  // Lower temperature for more structured output
		"max_tokens":   2000, // Larger output for detailed analysis
		"top_p":        0.9,
		"stop":         []string{"```", "</s>", "[INST]"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	log.Printf("Sending meta-LLM request with timeout of %v", a.requestTimeout)
	startTime := time.Now()
	
	// Send the request
	resp, err := client.Post(a.llmServerURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to query meta-LLM: %w", err)
	}
	defer resp.Body.Close()
	
	log.Printf("Received meta-LLM response in %v", time.Since(startTime))
	
	// Read full response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read meta-LLM response: %w", err)
	}
	
	// Extract the JSON response based on the LLM server format
	var rawResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &rawResponse); err != nil {
		return nil, fmt.Errorf("failed to parse meta-LLM response: %w", err)
	}
	
	// Handle different LLM server response formats
	var jsonContent string
	
	// Try to extract the content based on server format
	if content, ok := rawResponse["content"]; ok {
		// Direct content field (like your server)
		jsonContent, ok = content.(string)
		if !ok {
			return nil, fmt.Errorf("content field is not a string")
		}
	} else if choices, ok := rawResponse["choices"]; ok {
		// Standard OpenAI-style format
		choicesArr, ok := choices.([]interface{})
		if !ok || len(choicesArr) == 0 {
			return nil, fmt.Errorf("choices field is invalid or empty")
		}
		
		choice, ok := choicesArr[0].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("choice is not an object")
		}
		
		if text, ok := choice["text"]; ok {
			jsonContent, ok = text.(string)
			if !ok {
				return nil, fmt.Errorf("text field is not a string")
			}
		} else if content, ok := choice["content"]; ok {
			jsonContent, ok = content.(string)
			if !ok {
				return nil, fmt.Errorf("content field is not a string")
			}
		} else {
			return nil, fmt.Errorf("no text or content field in choice")
		}
	} else {
		return nil, fmt.Errorf("unrecognized LLM response format")
	}
	
	// Clean up the content
	jsonContent = strings.TrimSpace(jsonContent)
	
	// Try to extract JSON object
	if !strings.HasPrefix(jsonContent, "{") {
		if jsonStart := strings.Index(jsonContent, "{"); jsonStart >= 0 {
			if jsonEnd := strings.LastIndex(jsonContent, "}"); jsonEnd > jsonStart {
				jsonContent = jsonContent[jsonStart : jsonEnd+1]
			}
		}
	}
	
	// Parse the structured response
	var metaResponse MetaLLMResponse
	if err := json.Unmarshal([]byte(jsonContent), &metaResponse); err != nil {
		return nil, fmt.Errorf("failed to parse meta-LLM JSON response: %w\nContent: %s", err, jsonContent)
	}
	
	return &metaResponse, nil
}

// selectPromptForFileGroup chooses the most appropriate prompt template for a group of files
func (a *CodeAnalyzer) selectPromptForFileGroup(fileGroup []string, templates *PromptTemplates) string {
	// Count file types
	hasMiddleware := false
	hasRequestHandlers := false
	hasSecurityChecks := false
	
	for _, file := range fileGroup {
		fileName := strings.ToLower(filepath.Base(file))
		
		// Check for middleware files
		if strings.Contains(fileName, "middleware") || 
		   strings.Contains(fileName, "filter") ||
		   strings.Contains(fileName, "interceptor") {
			hasMiddleware = true
		}
		
		// Check for request handling files
		if strings.Contains(fileName, "request") ||
		   strings.Contains(fileName, "controller") ||
		   strings.Contains(fileName, "view") ||
		   strings.Contains(fileName, "route") ||
		   strings.Contains(fileName, "handler") {
			hasRequestHandlers = true
		}
		
		// Check for security related files
		if strings.Contains(fileName, "security") ||
		   strings.Contains(fileName, "auth") ||
		   strings.Contains(fileName, "permission") ||
		   strings.Contains(fileName, "access") {
			hasSecurityChecks = true
		}
	}
	
	// Select the most appropriate prompt
	if hasMiddleware {
		return templates.MiddlewarePrompt
	} else if hasRequestHandlers {
		return templates.RequestHandlingPrompt
	} else if hasSecurityChecks {
		return templates.SecurityCheckPrompt
	}
	
	// Default to main analysis prompt
	return templates.MainAnalysisPrompt
}

// useMetaLLMForFileFiltering uses the meta-LLM's analysis to help filter relevant files
func (a *CodeAnalyzer) useMetaLLMForFileFiltering(files []string, analysis *VulnerabilityAnalysis, filterPrompt string) []string {
	var relevantFiles []string
	
	// First pass: filter based on patterns and keywords
	for _, file := range files {
		fileName := strings.ToLower(filepath.Base(file))
		score := 0.0
		
		// Check for relevant file patterns
		for _, pattern := range analysis.RelevantFilePatterns {
			if strings.Contains(fileName, strings.ToLower(pattern)) {
				score += 0.5
			}
		}
		
		// Check for keywords with weighted importance
		fileContent, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}
		
		contentLower := strings.ToLower(string(fileContent))
		for keyword, importance := range analysis.KeywordImportance {
			if strings.Contains(contentLower, strings.ToLower(keyword)) {
				score += importance
			}
		}
		
		// If the file scores high enough, consider it relevant
		if score >= 0.7 {
			relevantFiles = append(relevantFiles, file)
		}
	}
	
	log.Printf("Meta-LLM file filtering identified %d out of %d files as relevant", 
		len(relevantFiles), len(files))
	
	return relevantFiles
}

// validateResults uses the result validation prompt to verify and rank results
func (a *CodeAnalyzer) validateResults(functions []IdentifiedFunction, validationPrompt string, vulnDetails string) []IdentifiedFunction {
	if len(functions) == 0 {
		return functions
	}
	
	// Create a validation prompt
	prompt := fmt.Sprintf(`[INST] %s

VULNERABILITY DETAILS:
%s

IDENTIFIED FUNCTIONS:
%s

Respond with a JSON array of the validated functions, including adjusted confidence scores. [/INST]`,
		validationPrompt, vulnDetails, formatFunctionsForValidation(functions))
	
	// Query the LLM
	validatedFunctions, err := a.debugQueryLLM(prompt)
	if err != nil {
		log.Printf("Warning: Result validation failed: %v", err)
		return functions
	}
	
	if len(validatedFunctions) == 0 {
		log.Printf("Warning: Result validation returned empty results, using original results")
		return functions
	}
	
	log.Printf("Result validation adjusted %d functions", len(validatedFunctions))
	return validatedFunctions
}

// formatFunctionsForValidation formats the functions for the validation prompt
func formatFunctionsForValidation(functions []IdentifiedFunction) string {
	var result strings.Builder
	
	for i, fn := range functions {
		result.WriteString(fmt.Sprintf("%d. Function: %s.%s\n", 
			i+1, fn.PackagePath, fn.FunctionName))
		result.WriteString(fmt.Sprintf("   Confidence: %.2f\n", fn.Confidence))
		result.WriteString(fmt.Sprintf("   Reasoning: %s\n\n", fn.Reasoning))
	}
	
	return result.String()
}

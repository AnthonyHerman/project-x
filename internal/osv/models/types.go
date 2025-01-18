// internal/osv/models/types.go
package models

// Entry represents the root structure of an OSV vulnerability file
type Entry struct {
	ID        string `json:"id"`
	Summary   string `json:"summary"`
	Details   string `json:"details"`
	Modified  string `json:"modified"`
	Published string `json:"published"`
	Affected  []Affected `json:"affected"`
}

type Affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced,omitempty"`
			Fixed      string `json:"fixed,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
	EcosystemSpecific struct {
		Imports []Import `json:"imports,omitempty"`
	} `json:"ecosystem_specific"`
}

type Import struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols,omitempty"`
}

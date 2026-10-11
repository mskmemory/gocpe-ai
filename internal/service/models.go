// Package service implements application operations independently of HTTP and PostgreSQL.
package service

import (
	"encoding/json"
	"time"
)

type Provider string

type Package struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Vendor         string   `json:"vendor,omitempty"`
	Version        string   `json:"version,omitempty"`
	Ecosystem      string   `json:"ecosystem,omitempty"`
	Namespace      string   `json:"namespace,omitempty"`
	RepositoryURLs []string `json:"repository_urls,omitempty"`
	ExistingCPEs   []string `json:"existing_cpes,omitempty"`
	ExistingPURLs  []string `json:"existing_purls,omitempty"`
}

type PackageInput struct {
	Kind     string    `json:"kind"`
	Packages []Package `json:"packages"`
}

type SBOMInput struct {
	Kind     string         `json:"kind"`
	Format   string         `json:"format"`
	Document map[string]any `json:"document"`
}

type Options struct {
	Provider      Provider `json:"provider"`
	Model         string   `json:"model"`
	Targets       []string `json:"targets,omitempty"`
	MaxCandidates int      `json:"max_candidates,omitempty"`
}

type CreateResolution struct {
	Input   json.RawMessage `json:"input"`
	Options Options         `json:"options"`
}

type ErrorDetail struct {
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}

type Error struct {
	Code      string        `json:"code"`
	Message   string        `json:"message"`
	RequestID string        `json:"request_id"`
	Details   []ErrorDetail `json:"details,omitempty"`
}

type ErrorResponse struct {
	Error Error `json:"error"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens,omitempty"`
	OutputTokens int `json:"output_tokens,omitempty"`
	Calls        int `json:"calls"`
}

type RunMetadata struct {
	InputSHA256   string `json:"input_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
	PromptVersion string `json:"prompt_version"`
	RuleVersion   string `json:"rule_version"`
	SchemaVersion string `json:"schema_version"`
	Usage         Usage  `json:"usage"`
	Entrypoint    string `json:"entrypoint"`
}

type Job struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Options   Options   `json:"options"`
	Progress  struct {
		Total     int `json:"total"`
		Processed int `json:"processed"`
	} `json:"progress"`
	RunMetadata RunMetadata `json:"run_metadata"`
	Errors      []Error     `json:"errors"`
}

type Verification struct {
	Source      string     `json:"source"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	Scope       string     `json:"scope"`
	Complete    bool       `json:"complete"`
	CheckedAt   *time.Time `json:"checked_at,omitempty"`
	EvidenceIDs []string   `json:"evidence_ids"`
}

type Identity struct {
	Status            string   `json:"status"`
	SupportingFields  []string `json:"supporting_fields"`
	ConflictingFields []string `json:"conflicting_fields"`
	MissingFields     []string `json:"missing_fields"`
}

type Evidence struct {
	ID             string         `json:"id"`
	Source         string         `json:"source"`
	SourceRecordID string         `json:"source_record_id,omitempty"`
	ReferenceURL   string         `json:"reference_url,omitempty"`
	Query          map[string]any `json:"query"`
	ObservedAt     time.Time      `json:"observed_at"`
	ResponseSHA256 string         `json:"response_sha256"`
	Scope          string         `json:"scope"`
	MatchKind      string         `json:"match_kind"`
	FromCache      bool           `json:"from_cache"`
}

type Candidate struct {
	ID            string       `json:"id"`
	Value         string       `json:"value"`
	Origin        string       `json:"origin"`
	Scope         string       `json:"scope"`
	Verification  Verification `json:"verification"`
	Identity      Identity     `json:"identity"`
	VersionStatus string       `json:"version_status"`
	Evidence      []Evidence   `json:"evidence"`
}

type ResultSet struct {
	Decision             string       `json:"decision"`
	ReasonCodes          []string     `json:"reason_codes"`
	Lookup               Verification `json:"lookup"`
	Candidates           []Candidate  `json:"candidates"`
	SelectedCandidateIDs []string     `json:"selected_candidate_ids"`
}

type ComponentResult struct {
	ComponentID   string     `json:"component_id"`
	Ordinal       int        `json:"ordinal"`
	SourcePointer string     `json:"source_pointer"`
	Input         Package    `json:"input"`
	CPE           *ResultSet `json:"cpe,omitempty"`
	PURL          *ResultSet `json:"purl,omitempty"`
	Errors        []Error    `json:"errors"`
}

type ResultPage struct {
	JobID         string            `json:"job_id"`
	SchemaVersion string            `json:"schema_version"`
	Items         []ComponentResult `json:"items"`
	NextCursor    string            `json:"next_cursor,omitempty"`
}

type ProviderInfo struct {
	Provider Provider `json:"provider"`
	Models   []string `json:"models"`
}

type ProviderList struct {
	Items []ProviderInfo `json:"items"`
}

type CPE struct {
	CPENameID        string    `json:"cpe_name_id"`
	CPEName          string    `json:"cpe_name"`
	Vendor           string    `json:"vendor"`
	Product          string    `json:"product"`
	Version          string    `json:"version"`
	Deprecated       bool      `json:"deprecated"`
	ReplacedBy       []string  `json:"replaced_by"`
	Titles           []string  `json:"titles"`
	SourceModifiedAt time.Time `json:"source_modified_at"`
	FetchedAt        time.Time `json:"fetched_at"`
}

type PURL struct {
	ID            string            `json:"id"`
	CanonicalPURL string            `json:"canonical_purl"`
	Type          string            `json:"type"`
	Namespace     string            `json:"namespace,omitempty"`
	Name          string            `json:"name"`
	Version       string            `json:"version,omitempty"`
	Qualifiers    map[string]string `json:"qualifiers"`
	Subpath       string            `json:"subpath,omitempty"`
	OSVRecordIDs  []string          `json:"osv_record_ids"`
	ObservedAt    time.Time         `json:"observed_at"`
}

type CPEPage struct {
	Items      []CPE  `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Coverage   string `json:"coverage"`
}

type PURLPage struct {
	Items      []PURL `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Coverage   string `json:"coverage"`
}

type PackageSearchRequest struct {
	Name           string   `json:"name"`
	Vendor         string   `json:"vendor"`
	Version        string   `json:"version,omitempty"`
	Ecosystem      string   `json:"ecosystem,omitempty"`
	Namespace      string   `json:"namespace,omitempty"`
	RepositoryURLs []string `json:"repository_urls,omitempty"`
	ExistingCPEs   []string `json:"existing_cpes,omitempty"`
	ExistingPURLs  []string `json:"existing_purls,omitempty"`
	Options        Options  `json:"options"`
}

type Input struct {
	Kind     string          `json:"kind"`
	Packages []Package       `json:"packages,omitempty"`
	Format   string          `json:"format,omitempty"`
	Document json.RawMessage `json:"document,omitempty"`
}

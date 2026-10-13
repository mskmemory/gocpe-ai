// Package store defines the persistence contract shared by the HTTP API,
// service layer, worker and CLI. It contains no SQL. The PostgreSQL
// implementation lives in internal/store/postgres.
//
// The types here are persistence models, not HTTP DTOs. The API layer maps
// them to the OpenAPI schemas (signing cursors, adding request_id, etc.).
// Callers must authenticate owners before calling owner-scoped methods.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Sentinel errors. Implementations wrap them with context; use errors.Is.
var (
	ErrWorkerUnavailable = errors.New("store: worker unavailable")
	// ErrNotFound: missing record, another owner's job, or an expired job.
	ErrNotFound = errors.New("store: not found")
	// ErrInvalid: input rejected by validation or a database constraint.
	ErrInvalid = errors.New("store: invalid input")
	// ErrConflict: state or uniqueness conflict (e.g. component already done).
	ErrConflict = errors.New("store: conflict")
	// ErrIdempotencyConflict: the key is live and was used for a different request.
	ErrIdempotencyConflict = errors.New("store: idempotency key reused with different request")
	// ErrNotReady: results requested for a non-terminal job.
	ErrNotReady = errors.New("store: results not ready")
	// ErrLeaseLost: the worker lease expired, was taken over, or the job ended.
	ErrLeaseLost = errors.New("store: lease lost")
	// ErrNoJob: no job is currently available for a worker.
	ErrNoJob = errors.New("store: no job available")
	// ErrHashCollision: same SHA-256 but different canonical identifier text.
	ErrHashCollision = errors.New("store: identifier hash collision")
)

// JobStatus values mirror the OpenAPI Job.status enum.
type JobStatus string

const (
	StatusQueued     JobStatus = "queued"
	StatusRunning    JobStatus = "running"
	StatusCancelling JobStatus = "cancelling"
	StatusCompleted  JobStatus = "completed"
	StatusPartial    JobStatus = "partial"
	StatusFailed     JobStatus = "failed"
	StatusCancelled  JobStatus = "cancelled"
)

// Terminal reports whether no further state transition is allowed.
func (s JobStatus) Terminal() bool {
	switch s {
	case StatusCompleted, StatusPartial, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// Endpoint identifies the creation entrypoint. It is part of the
// idempotency request hash and is stored in run_metadata.entrypoint.
type Endpoint string

const (
	EndpointResolution    Endpoint = "resolution"
	EndpointPackageSearch Endpoint = "package_search"
)

// ---- Dictionary (NVD CPE / PURL / OSV) ----

// CPERecord is one NVD CPE dictionary entry. Part/Vendor/Product/Version and
// Attributes are derived by the store from Name with a CPE 2.3 parser; they
// are populated on read and ignored on write.
type CPERecord struct {
	NameID           string // NVD cpeNameId (UUID)
	Name             string // cpeName exactly as returned by NVD
	Part             string
	Vendor           string
	Product          string
	Version          string
	Attributes       map[string]string // update, edition, language, sw_edition, target_sw, target_hw, other (FS form)
	Titles           []string
	Deprecated       bool
	ReplacedBy       []string // replacement cpeNameIds; may reference rows not yet fetched
	SourceModifiedAt time.Time
	FetchedAt        time.Time
	Raw              json.RawMessage // original NVD product object
}

// UpsertResult tells whether a dictionary write was applied. Applied=false
// means the stored row has a newer source modification time (stale input).
type UpsertResult struct {
	Applied bool
}

// CPEQuery filters /v1/cpes. Empty strings mean "no filter". Deprecated nil
// means no filter; the API maps its default (false) to a non-nil pointer.
type CPEQuery struct {
	Query      string // case-insensitive substring of cpe_name or any title
	Vendor     string // exact FS-form match
	Product    string // exact FS-form match
	Deprecated *bool
	After      string // keyset boundary: last cpe_name_id of the previous page
	Limit      int    // 0 => 100, max 200
}

// CPEPage is one keyset page. NextAfter is empty on the last page.
type CPEPage struct {
	Items     []CPERecord
	NextAfter string
}

// PURL is a canonicalized Package URL row. A row by itself does not mean the
// PURL was externally confirmed.
type PURL struct {
	ID                   string
	Canonical            string
	NormalizationVersion string
	Type                 string
	Namespace            string // empty when absent
	Name                 string
	Version              string // empty when absent
	Qualifiers           map[string]string
	Subpath              string    // empty when absent
	OSVRecordIDs         []string  // populated by SearchPURLs (non-withdrawn records only)
	ObservedAt           time.Time // latest fetched_at of the related OSV records (SearchPURLs)
}

// PURLMapping states how an OSV affected entry was mapped to a PURL.
type PURLMapping string

const (
	PURLExplicit    PURLMapping = "explicit"    // affected[].package.purl was present
	PURLDerived     PURLMapping = "derived"     // derived from ecosystem/name by a supported rule
	PURLUnavailable PURLMapping = "unavailable" // unsupported ecosystem or invalid PURL
)

// OSVAffected is one element of an OSV record's affected[] array.
type OSVAffected struct {
	Index     int // position in affected[]
	Ecosystem string
	Name      string
	PURL      string // PURL to link (explicit or derived); empty when unavailable
	RawPURL   string // affected[].package.purl as published, if any
	Mapping   PURLMapping
	Affected  json.RawMessage // original affected[] element
	PURLID    string          // set on read
}

// OSVRecord is an OSV vulnerability record used as evidence.
type OSVRecord struct {
	ID          string
	ModifiedAt  time.Time
	WithdrawnAt *time.Time
	FetchedAt   time.Time
	Raw         json.RawMessage
	Affected    []OSVAffected
}

// PURLQuery filters /v1/purls. Only PURLs linked to a non-withdrawn OSV
// record are returned.
type PURLQuery struct {
	Query     string // case-insensitive substring of canonical_purl
	Type      string
	Namespace string
	Name      string
	After     string // last purl id of the previous page
	Limit     int
}

// PURLPage is one keyset page. NextAfter is empty on the last page.
type PURLPage struct {
	Items     []PURL
	NextAfter string
}

// Dictionary persists the shared NVD/OSV/PURL dictionary.
type Dictionary interface {
	UpsertCPE(ctx context.Context, rec CPERecord) (UpsertResult, error)
	GetCPE(ctx context.Context, nameID string) (CPERecord, error)
	SearchCPEs(ctx context.Context, q CPEQuery) (CPEPage, error)
	UpsertOSV(ctx context.Context, rec OSVRecord) (UpsertResult, error)
	GetOSV(ctx context.Context, id string) (OSVRecord, error)
	// EnsurePURL parses, canonicalizes and stores a PURL, returning the row.
	// Use only for PURLs that are being linked to external evidence.
	EnsurePURL(ctx context.Context, raw string) (PURL, error)
	SearchPURLs(ctx context.Context, q PURLQuery) (PURLPage, error)
}

// ---- Jobs ----

// NewComponent is one normalized input component. Ordinal is its slice index.
type NewComponent struct {
	ID            string          // bom-ref / SPDXID / package id / generated stable id
	SourcePointer string          // JSON Pointer into the input document ("" for root)
	Input         json.RawMessage // normalized Package object (OpenAPI Package)
	Raw           json.RawMessage // raw values before normalization (JSON object)
}

// NewJob is a validated creation request. The service layer validates the
// request against OpenAPI, applies defaults and normalizes components.
type NewJob struct {
	Owner          string
	Endpoint       Endpoint
	IdempotencyKey string          // optional, 1..128 chars
	Request        json.RawMessage // original request body before defaults (hashed for idempotency)
	InputKind      string          // packages | sbom
	Input          json.RawMessage // input document to retain (request.input or the package-search request)
	Provider       string
	Model          string
	Options        json.RawMessage // effective options after defaults
	RunMetadata    json.RawMessage // prompt/rule/schema versions, entrypoint, usage
	Components     []NewComponent
}

// Job is the persisted job row (input_document excluded).
type Job struct {
	ID           string
	Owner        string
	Status       JobStatus
	Provider     string
	Model        string
	InputKind    string
	Options      json.RawMessage
	RunMetadata  json.RawMessage // includes input_sha256 and config_sha256
	Errors       json.RawMessage // JSON array of {code,message[,pointer]}
	InputSHA256  string
	ConfigSHA256 string
	Total        int
	Processed    int
	Attempts     int
	CreatedAt    time.Time
	UpdatedAt    time.Time
	FinishedAt   *time.Time
	ExpiresAt    time.Time
	Deadline     time.Time
}

// ErrorEntry is a job/component level error. request_id is not stored; the
// API layer decides how to populate it.
type ErrorEntry struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Pointer string `json:"pointer,omitempty"`
}

// Verification mirrors OpenAPI Verification.
type Verification struct {
	Source      string     `json:"source"` // nvd | osv
	Kind        string     `json:"kind"`   // cpe_registration | purl_match | ecosystem_name_match | lookup
	Status      string     `json:"status"` // confirmed | no_evidence | unsupported | error | not_checked
	Scope       string     `json:"scope"`  // product | package | version
	Complete    bool       `json:"complete"`
	CheckedAt   *time.Time `json:"checked_at,omitempty"`
	EvidenceIDs []string   `json:"evidence_ids"`
}

// Identity mirrors OpenAPI Identity.
type Identity struct {
	Status            string   `json:"status"`
	SupportingFields  []string `json:"supporting_fields"`
	ConflictingFields []string `json:"conflicting_fields"`
	MissingFields     []string `json:"missing_fields"`
}

// Evidence is an immutable, job-owned snapshot of an external observation.
type Evidence struct {
	ID             string // caller-generated UUID (see NewID) so candidates can reference it
	Source         string // nvd | osv
	SourceRecordID string
	ReferenceURL   string
	Query          json.RawMessage // JSON object
	ObservedAt     time.Time
	ResponseSHA256 string
	Scope          string
	MatchKind      string
	FromCache      bool
	Snapshot       json.RawMessage // copied external content (never re-read from the dictionary)
}

// Candidate is one ranked CPE/PURL candidate. Rank is its slice index + 1.
// Verification.EvidenceIDs defines the candidate_evidence links.
type Candidate struct {
	ID            string // optional on write; generated when empty
	Value         string
	Origin        string // sbom | ai | nvd | osv
	Scope         string
	Verification  Verification
	Identity      Identity
	VersionStatus string
	Selected      bool
	CPENameID     string     // optional link to nvd_cpes (cpe target only)
	PURLID        string     // optional link to purls (purl target only)
	Evidence      []Evidence // populated on read
}

// TargetResult is the per-target (cpe/purl) decision for a component.
// Lookup.EvidenceIDs defines the target_evidence links.
type TargetResult struct {
	Target      string // cpe | purl
	Decision    string // accepted | review_required | unresolved
	ReasonCodes []string
	Lookup      Verification
	Candidates  []Candidate
	Evidence    []Evidence // lookup evidence, populated on read
}

// ComponentOutcome is written atomically when a component finishes.
type ComponentOutcome struct {
	ComponentID string
	Errors      []ErrorEntry
	Evidence    []Evidence // new snapshots; may also reference earlier snapshots of the same job
	Targets     []TargetResult
}

// Component is a stored component as seen by a worker or the results API.
type Component struct {
	JobID         string
	ID            string
	Ordinal       int
	SourcePointer string
	Input         json.RawMessage
	Raw           json.RawMessage
	State         string // pending | running | done
	Errors        json.RawMessage
}

// ComponentResult is one item of the results API.
type ComponentResult struct {
	Component Component
	Targets   []TargetResult // ordered: cpe, purl
}

// ResultQuery pages components by ordinal. AfterOrdinal < 0 starts at the top.
type ResultQuery struct {
	AfterOrdinal int
	Limit        int
}

// ResultPage is one page. HasMore reports whether NextAfterOrdinal is valid.
type ResultPage struct {
	Job              Job
	Items            []ComponentResult
	HasMore          bool
	NextAfterOrdinal int
}

// Jobs is used by the API/service layer. Every method is owner-scoped.
type Jobs interface {
	// CreateJob stores the job, its components and the idempotency key in
	// one transaction. created=false means an idempotent replay.
	CreateJob(ctx context.Context, j NewJob) (job Job, created bool, err error)
	GetJob(ctx context.Context, owner, id string) (Job, error)
	// CancelJob: queued->cancelled, running->cancelling, otherwise unchanged.
	CancelJob(ctx context.Context, owner, id string) (Job, error)
	ListResults(ctx context.Context, owner, id string, q ResultQuery) (ResultPage, error)
}

// Lease identifies a worker's exclusive claim on a job.
type Lease struct {
	JobID string
	Token string
}

// AcquireOptions controls job claiming.
type AcquireOptions struct {
	LeaseDuration time.Duration
	MaxAttempts   int // jobs with attempts >= MaxAttempts are not claimed
}

// Usage is an increment of provider usage, added to run_metadata.usage.
type Usage struct {
	InputTokens  int64
	OutputTokens int64
	Calls        int64
}

// ReapResult counts jobs finalized by ReapExpired.
type ReapResult struct {
	Cancelled int64
	Failed    int64
	Partial   int64
}

// PurgeResult counts deleted rows.
type PurgeResult struct {
	Jobs            int64
	IdempotencyKeys int64
}

// Queue is used by workers and maintenance tasks.
type Queue interface {
	AcquireJob(ctx context.Context, o AcquireOptions) (Lease, Job, error)
	// Heartbeat extends the lease and returns the job so the worker can
	// observe cancelling or an exceeded deadline.
	Heartbeat(ctx context.Context, l Lease, d time.Duration) (Job, error)
	// NextComponents marks up to limit unfinished components running and
	// returns them in ordinal order (including ones left running by a crash).
	NextComponents(ctx context.Context, l Lease, limit int) ([]Component, error)
	CompleteComponent(ctx context.Context, l Lease, o ComponentOutcome) error
	AddUsage(ctx context.Context, l Lease, u Usage) error
	// FinishJob ends a job with completed/partial/failed. A job that is
	// cancelling ends as cancelled regardless of the requested status.
	FinishJob(ctx context.Context, l Lease, status JobStatus, errs []ErrorEntry) (Job, error)
	// ReapExpired finalizes jobs with expired leases or deadlines.
	ReapExpired(ctx context.Context, maxAttempts int) (ReapResult, error)
	// PurgeExpired deletes expired idempotency keys and terminal jobs past
	// retention (CASCADE removes their components, results and evidence).
	PurgeExpired(ctx context.Context, batch int) (PurgeResult, error)
}

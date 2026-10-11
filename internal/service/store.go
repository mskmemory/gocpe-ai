package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("idempotency conflict")
	ErrUnavailable = errors.New("backend unavailable")
	ErrRateLimited = errors.New("rate limited")
)

type Component struct {
	Package       Package
	Ordinal       int
	SourcePointer string
	RawValues     json.RawMessage
}
type StoredJob struct {
	OwnerID string
	Job     Job
}

// Admission is persisted atomically with components and the idempotency key.
// An unexpired owner+key with the same RequestHash returns the original job.
// A different hash returns ErrConflict. Empty keys never deduplicate.
// Check backend/worker readiness before accepting NEW work; replay stays available.
type Admission struct {
	OwnerID        string
	Job            Job
	InputKind      string
	InputDocument  json.RawMessage
	Components     []Component
	IdempotencyKey string
	RequestHash    string
	KeyExpiresAt   time.Time
}
type PageQuery struct {
	Limit int
	After string
}
type CPEQuery struct {
	PageQuery
	Q, Vendor, Product string
	Deprecated         bool
}
type PURLQuery struct {
	PageQuery
	Q, Type, Namespace, Name string
}

// Store is the integration boundary for the separate PostgreSQL implementation.
// Every job read/write enforces owner and expires_at > now; otherwise ErrNotFound.
// Returned values are owned by the caller. Lists return at most Limit rows ordered
// by ordinal (results) or UUID (dictionary). PURLs require non-withdrawn OSV evidence.
type Store interface {
	Admit(context.Context, Admission) (StoredJob, error)
	GetJob(context.Context, string, string, time.Time) (StoredJob, error)
	// Cancel atomically changes queued to cancelled, running to cancelling.
	// Terminal states remain unchanged. The bool means the request was accepted.
	Cancel(context.Context, string, string, time.Time) (StoredJob, bool, error)
	Results(context.Context, string, string, PageQuery, time.Time) ([]ComponentResult, error)
	CPEs(context.Context, CPEQuery) ([]CPE, error)
	PURLs(context.Context, PURLQuery) ([]PURL, error)
}

// UnavailableStore is the production placeholder until DB/worker integration.
// It never fabricates queued jobs or successful empty dictionary responses.
type UnavailableStore struct{}

func (UnavailableStore) Admit(context.Context, Admission) (StoredJob, error) {
	return StoredJob{}, ErrUnavailable
}
func (UnavailableStore) GetJob(context.Context, string, string, time.Time) (StoredJob, error) {
	return StoredJob{}, ErrUnavailable
}
func (UnavailableStore) Cancel(context.Context, string, string, time.Time) (StoredJob, bool, error) {
	return StoredJob{}, false, ErrUnavailable
}
func (UnavailableStore) Results(context.Context, string, string, PageQuery, time.Time) ([]ComponentResult, error) {
	return nil, ErrUnavailable
}
func (UnavailableStore) CPEs(context.Context, CPEQuery) ([]CPE, error)    { return nil, ErrUnavailable }
func (UnavailableStore) PURLs(context.Context, PURLQuery) ([]PURL, error) { return nil, ErrUnavailable }

// Package apistore adapts persistence models to the public API contract.
package apistore

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/mskmemory/gocpe-ai/internal/service"
	"github.com/mskmemory/gocpe-ai/internal/store"
	"github.com/mskmemory/gocpe-ai/internal/store/postgres"
)

type Postgres struct {
	Repository *postgres.Store
	Ready      func(context.Context) bool
}

var _ service.Store = (*Postgres)(nil)

func mapped(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrWorkerUnavailable):
		return service.ErrUnavailable
	case errors.Is(err, store.ErrNotFound):
		return service.ErrNotFound
	case errors.Is(err, store.ErrIdempotencyConflict), errors.Is(err, store.ErrConflict):
		return service.ErrConflict
	case errors.Is(err, store.ErrNotReady):
		return &service.Fault{Status: 409, Code: "RESULTS_NOT_READY", Message: "Results are not ready"}
	case errors.Is(err, store.ErrInvalid):
		return service.Invalid("", "Invalid persistence input")
	default:
		return service.ErrUnavailable
	}
}
func publicErrors(raw json.RawMessage) ([]service.Error, error) {
	var entries []store.ErrorEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	out := []service.Error{}
	for _, v := range entries {
		e := service.Error{Code: v.Code, Message: v.Message, RequestID: "persisted"}
		if v.Pointer != "" {
			e.Details = []service.ErrorDetail{{Pointer: v.Pointer, Message: v.Message}}
		}
		out = append(out, e)
	}
	return out, nil
}
func publicJob(j store.Job) (service.StoredJob, error) {
	out := service.StoredJob{OwnerID: j.Owner, Job: service.Job{ID: j.ID, Status: string(j.Status), CreatedAt: j.CreatedAt, UpdatedAt: j.UpdatedAt, ExpiresAt: j.ExpiresAt}}
	out.Job.Progress.Total = j.Total
	out.Job.Progress.Processed = j.Processed
	if e := json.Unmarshal(j.Options, &out.Job.Options); e != nil {
		return out, e
	}
	if e := json.Unmarshal(j.RunMetadata, &out.Job.RunMetadata); e != nil {
		return out, e
	}
	var e error
	out.Job.Errors, e = publicErrors(j.Errors)
	return out, e
}
func (p *Postgres) Admit(ctx context.Context, a service.Admission) (service.StoredJob, error) {
	options, e := json.Marshal(a.Job.Options)
	if e != nil {
		return service.StoredJob{}, e
	}
	metadata, e := json.Marshal(a.Job.RunMetadata)
	if e != nil {
		return service.StoredJob{}, e
	}
	j := store.NewJob{Owner: a.OwnerID, Endpoint: store.Endpoint(a.Job.RunMetadata.Entrypoint), IdempotencyKey: a.IdempotencyKey, Request: a.InputDocument, Input: a.InputDocument, InputKind: a.InputKind, Provider: string(a.Job.Options.Provider), Model: a.Job.Options.Model, Options: options, RunMetadata: metadata}
	for _, v := range a.Components {
		b, e := json.Marshal(v.Package)
		if e != nil {
			return service.StoredJob{}, e
		}
		j.Components = append(j.Components, store.NewComponent{ID: v.Package.ID, SourcePointer: v.SourcePointer, Input: b, Raw: v.RawValues})
	}
	// Admission is disabled until a real worker is ready. Idempotent replays
	// remain available and are checked by the repository before accepting new work.
	ready := p.Ready != nil && p.Ready(ctx)
	row, _, e := p.Repository.CreateJobIfReady(ctx, j, ready)
	if e != nil {
		return service.StoredJob{}, mapped(e)
	}
	return publicJob(row)
}
func (p *Postgres) GetJob(ctx context.Context, owner, id string, now time.Time) (service.StoredJob, error) {
	j, e := p.Repository.GetJob(ctx, owner, id)
	if e != nil {
		return service.StoredJob{}, mapped(e)
	}
	if !j.ExpiresAt.After(now) {
		return service.StoredJob{}, service.ErrNotFound
	}
	return publicJob(j)
}
func (p *Postgres) Cancel(ctx context.Context, owner, id string, now time.Time) (service.StoredJob, bool, error) {
	j, accepted, e := p.Repository.CancelJobWithOutcome(ctx, owner, id)
	if e != nil {
		return service.StoredJob{}, false, mapped(e)
	}
	if !j.ExpiresAt.After(now) {
		return service.StoredJob{}, false, service.ErrNotFound
	}
	out, e := publicJob(j)
	return out, accepted, e
}
func verification(v store.Verification) service.Verification {
	return service.Verification{Source: v.Source, Kind: v.Kind, Status: v.Status, Scope: v.Scope, Complete: v.Complete, CheckedAt: v.CheckedAt, EvidenceIDs: nonNil(v.EvidenceIDs)}
}
func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
func evidence(v store.Evidence) (service.Evidence, error) {
	e := service.Evidence{ID: v.ID, Source: v.Source, SourceRecordID: v.SourceRecordID, ReferenceURL: v.ReferenceURL, ObservedAt: v.ObservedAt, ResponseSHA256: v.ResponseSHA256, Scope: v.Scope, MatchKind: v.MatchKind, FromCache: v.FromCache}
	err := json.Unmarshal(v.Query, &e.Query)
	return e, err
}
func result(v store.ComponentResult) (service.ComponentResult, error) {
	r := service.ComponentResult{ComponentID: v.Component.ID, Ordinal: v.Component.Ordinal, SourcePointer: v.Component.SourcePointer}
	if e := json.Unmarshal(v.Component.Input, &r.Input); e != nil {
		return r, e
	}
	var e error
	r.Errors, e = publicErrors(v.Component.Errors)
	if e != nil {
		return r, e
	}
	for _, target := range v.Targets {
		set := &service.ResultSet{Decision: target.Decision, ReasonCodes: nonNil(target.ReasonCodes), Lookup: verification(target.Lookup), Candidates: []service.Candidate{}, SelectedCandidateIDs: []string{}}
		for _, c := range target.Candidates {
			candidate := service.Candidate{ID: c.ID, Value: c.Value, Origin: c.Origin, Scope: c.Scope, Verification: verification(c.Verification), Identity: service.Identity{Status: c.Identity.Status, SupportingFields: nonNil(c.Identity.SupportingFields), ConflictingFields: nonNil(c.Identity.ConflictingFields), MissingFields: nonNil(c.Identity.MissingFields)}, VersionStatus: c.VersionStatus, Evidence: []service.Evidence{}}
			for _, v := range c.Evidence {
				ev, e := evidence(v)
				if e != nil {
					return r, e
				}
				candidate.Evidence = append(candidate.Evidence, ev)
			}
			set.Candidates = append(set.Candidates, candidate)
			if c.Selected {
				set.SelectedCandidateIDs = append(set.SelectedCandidateIDs, c.ID)
			}
		}
		if target.Target == "cpe" {
			r.CPE = set
		} else {
			r.PURL = set
		}
	}
	return r, nil
}
func (p *Postgres) Results(ctx context.Context, owner, id string, q service.PageQuery, now time.Time) ([]service.ComponentResult, error) {
	if _, e := p.GetJob(ctx, owner, id, now); e != nil {
		return nil, e
	}
	after := -1
	if q.After != "" {
		n, e := strconv.Atoi(q.After)
		if e != nil {
			return nil, service.Invalid("", "Invalid cursor")
		}
		after = n
	}
	out := []service.ComponentResult{}
	for len(out) < q.Limit {
		limit := min(q.Limit-len(out), 200)
		page, e := p.Repository.ListResults(ctx, owner, id, store.ResultQuery{AfterOrdinal: after, Limit: limit})
		if e != nil {
			return nil, mapped(e)
		}
		for _, v := range page.Items {
			r, e := result(v)
			if e != nil {
				return nil, e
			}
			out = append(out, r)
		}
		if !page.HasMore {
			break
		}
		after = page.NextAfterOrdinal
	}
	return out, nil
}
func (p *Postgres) CPEs(ctx context.Context, q service.CPEQuery) ([]service.CPE, error) {
	out := []service.CPE{}
	after := q.After
	for len(out) < q.Limit {
		page, e := p.Repository.SearchCPEs(ctx, store.CPEQuery{Query: q.Q, Vendor: q.Vendor, Product: q.Product, Deprecated: &q.Deprecated, After: after, Limit: min(q.Limit-len(out), 200)})
		if e != nil {
			return nil, mapped(e)
		}
		for _, v := range page.Items {
			out = append(out, service.CPE{CPENameID: v.NameID, CPEName: v.Name, Vendor: v.Vendor, Product: v.Product, Version: v.Version, Deprecated: v.Deprecated, ReplacedBy: nonNil(v.ReplacedBy), Titles: nonNil(v.Titles), SourceModifiedAt: v.SourceModifiedAt, FetchedAt: v.FetchedAt})
		}
		if page.NextAfter == "" {
			break
		}
		after = page.NextAfter
	}
	return out, nil
}
func (p *Postgres) PURLs(ctx context.Context, q service.PURLQuery) ([]service.PURL, error) {
	out := []service.PURL{}
	after := q.After
	for len(out) < q.Limit {
		page, e := p.Repository.SearchPURLs(ctx, store.PURLQuery{Query: q.Q, Type: q.Type, Namespace: q.Namespace, Name: q.Name, After: after, Limit: min(q.Limit-len(out), 200)})
		if e != nil {
			return nil, mapped(e)
		}
		for _, v := range page.Items {
			qualifiers := v.Qualifiers
			if qualifiers == nil {
				qualifiers = map[string]string{}
			}
			out = append(out, service.PURL{ID: v.ID, CanonicalPURL: v.Canonical, Type: v.Type, Namespace: v.Namespace, Name: v.Name, Version: v.Version, Qualifiers: qualifiers, Subpath: v.Subpath, OSVRecordIDs: nonNil(v.OSVRecordIDs), ObservedAt: v.ObservedAt})
		}
		if page.NextAfter == "" {
			break
		}
		after = page.NextAfter
	}
	return out, nil
}

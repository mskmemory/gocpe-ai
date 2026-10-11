// Package resolve exposes external verification independently of AI and workers.
package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"github.com/mskmemory/gocpe-ai/internal/nvd"
	"github.com/mskmemory/gocpe-ai/internal/osv"
	"github.com/mskmemory/gocpe-ai/internal/store"
	"time"
)

type NVDClient interface {
	Search(context.Context, nvd.Query) (nvd.Result, error)
}
type OSVClient interface {
	Query(context.Context, osv.Query) (osv.Result, error)
}
type External struct {
	NVD        NVDClient
	OSV        OSVClient
	Dictionary store.Dictionary
}
type Result struct {
	Target   store.TargetResult
	Evidence []store.Evidence
}

func base(target, source, scope string, o lookup.Observation, err error) Result {
	now := time.Now().UTC()
	status := "no_evidence"
	reasons := []string{}
	if err != nil {
		status = "error"
		reasons = append(reasons, o.Reason)
	}
	if errors.Is(err, lookup.ErrUnsupported) {
		status = "unsupported"
	}
	ids := []string{}
	for _, e := range o.Evidence {
		ids = append(ids, e.ID)
	}
	return Result{Target: store.TargetResult{Target: target, Decision: "unresolved", ReasonCodes: reasons, Lookup: store.Verification{Source: source, Kind: "lookup", Status: status, Scope: scope, Complete: o.Complete, CheckedAt: &now, EvidenceIDs: ids}}, Evidence: o.Evidence}
}
func identity() store.Identity {
	return store.Identity{Status: "insufficient", SupportingFields: []string{}, ConflictingFields: []string{}, MissingFields: []string{"independent_input_identity"}}
}

// CPE returns every registered candidate. Exact optionally tests a supplied CPE;
// it is never replaced by Query.MatchString and is not an identity assertion.
func (e *External) CPE(ctx context.Context, q nvd.Query, exact string) (Result, error) {
	got, err := e.NVD.Search(ctx, q)
	r := base("cpe", "nvd", "product", got.Observation, err)
	records := append([]store.CPERecord(nil), got.Records...)
	// A deprecated entry's replacement is a separate registered record.
	// Fetch each explicitly and retain both; never silently substitute it.
	replacements := map[string]bool{}
	for _, rec := range got.Records {
		if rec.Deprecated {
			for _, id := range rec.ReplacedBy {
				replacements[id] = true
			}
		}
	}
	for id := range replacements {
		replacement, fetchErr := e.NVD.Search(ctx, nvd.Query{NameID: id})
		r.Evidence = append(r.Evidence, replacement.Evidence...)
		records = append(records, replacement.Records...)
		if fetchErr != nil {
			r.Target.ReasonCodes = append(r.Target.ReasonCodes, "REPLACEMENT_LOOKUP_INCOMPLETE")
			r.Target.Lookup.Complete = false
			r.Target.Lookup.Status = "error"
			if err == nil {
				err = fetchErr
			}
		}
	}
	seen := map[string]bool{}
	for _, rec := range records {
		if seen[rec.NameID] {
			continue
		}
		seen[rec.NameID] = true
		if _, saveErr := e.Dictionary.UpsertCPE(ctx, rec); saveErr != nil {
			return r, saveErr
		}
		if exact != "" && !nvd.Registered(exact, rec.Name) {
			continue
		}
		v := r.Target.Lookup
		v.Kind = "cpe_registration"
		v.Status = "confirmed"
		ev := store.Evidence{ID: store.NewID(), Source: "nvd", SourceRecordID: rec.NameID, ReferenceURL: nvd.Endpoint, Query: mustJSON(map[string]any{"search": q, "replacement_lookup": replacements}), ObservedAt: rec.FetchedAt, Scope: "product", MatchKind: "cpe_registration", Snapshot: rec.Raw}
		r.Evidence = append(r.Evidence, ev)
		v.EvidenceIDs = []string{ev.ID}
		r.Target.Candidates = append(r.Target.Candidates, store.Candidate{Value: rec.Name, Origin: "nvd", Scope: "product", Verification: v, Identity: identity(), VersionStatus: "not_checked", CPENameID: rec.NameID})
		if rec.Deprecated {
			r.Target.ReasonCodes = append(r.Target.ReasonCodes, "DEPRECATED_CPE")
		}
	}
	if len(r.Target.Candidates) > 0 {
		r.Target.Decision = "review_required"
		if err == nil {
			r.Target.Lookup.Status = "confirmed"
		}
	}
	return r, err
}

// PURL performs package-level lookup. The original full identifier is retained;
// package-level evidence never upgrades version/qualifier/subpath verification.
func (e *External) PURL(ctx context.Context, raw string) (Result, error) {
	q, err := osv.PackageQuery(raw)
	if err != nil {
		o := lookup.Observation{}
		o.Fail(err)
		return base("purl", "osv", "package", o, err), err
	}
	got, err := e.OSV.Query(ctx, q)
	for i := range got.Evidence {
		original := got.Evidence[i].Query
		got.Evidence[i].Query, _ = json.Marshal(map[string]any{"original_purl": raw, "request": json.RawMessage(original), "confirmed_fields": []string{"type", "namespace", "name"}, "unchecked_fields": []string{"version", "qualifiers", "subpath"}})
	}
	r := base("purl", "osv", "package", got.Observation, err)
	kind := ""
	matched := []store.Evidence{}
	for _, rec := range got.Records {
		if _, saveErr := e.Dictionary.UpsertOSV(ctx, rec); saveErr != nil {
			return r, saveErr
		}
		for _, a := range rec.Affected {
			if k := osv.Match(q, a); k != "" {
				if rec.WithdrawnAt != nil {
					r.Target.ReasonCodes = append(r.Target.ReasonCodes, "WITHDRAWN_OSV_RECORD")
					continue
				}
				matched = append(matched, store.Evidence{ID: store.NewID(), Source: "osv", SourceRecordID: rec.ID, ReferenceURL: osv.Endpoint, Query: mustJSON(map[string]any{"original_purl": raw, "request": q, "affected_index": a.Index, "unchecked_fields": []string{"version", "qualifiers", "subpath"}}), ObservedAt: rec.FetchedAt, Scope: "package", MatchKind: k, Snapshot: rec.Raw})
				if kind != "purl_match" {
					kind = k
				}
			}
		}
	}
	v := r.Target.Lookup
	v.Kind = "lookup"
	if kind != "" {
		v.Kind = kind
		v.EvidenceIDs = []string{}
		for _, ev := range matched {
			if ev.MatchKind == kind {
				r.Evidence = append(r.Evidence, ev)
				v.EvidenceIDs = append(v.EvidenceIDs, ev.ID)
			}
		}
		v.Status = "confirmed"
		r.Target.Decision = "review_required"
		if err == nil {
			r.Target.Lookup.Status = "confirmed"
		}
	} else if err == nil {
		r.Target.ReasonCodes = append(r.Target.ReasonCodes, "OSV_NO_EVIDENCE")
	}
	r.Target.Candidates = []store.Candidate{{Value: raw, Origin: "sbom", Scope: "package", Verification: v, Identity: identity(), VersionStatus: "not_checked"}}
	return r, err
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

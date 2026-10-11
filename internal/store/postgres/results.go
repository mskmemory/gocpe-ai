package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/mskmemory/gocpe-ai/internal/store"
)

func oneOf(v string, values ...string) bool {
	for _, x := range values {
		if v == x {
			return true
		}
	}
	return false
}
func validVerification(v store.Verification, target string) bool {
	source := "osv"
	if target == "cpe" {
		source = "nvd"
	}
	return v.Source == source && oneOf(v.Status, "confirmed", "no_evidence", "unsupported", "error", "not_checked") && oneOf(v.Scope, "product", "package", "version") && ((target == "cpe" && oneOf(v.Kind, "lookup", "cpe_registration")) || (target == "purl" && oneOf(v.Kind, "lookup", "purl_match", "ecosystem_name_match"))) && (v.Status != "confirmed" || (v.CheckedAt != nil && len(v.EvidenceIDs) > 0))
}

// CompleteComponent writes all requested targets and immutable evidence in one
// transaction guarded by the current job lease. Done components cannot be rewritten.
func (s *Store) CompleteComponent(ctx context.Context, l store.Lease, o store.ComponentOutcome) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		j, e := lockLease(ctx, tx, l)
		if e != nil {
			return e
		}
		if j.Status != store.StatusRunning {
			return store.ErrLeaseLost
		}
		var state string
		e = tx.QueryRow(ctx, `SELECT state FROM resolution_components WHERE job_id=$1 AND component_id=$2 FOR UPDATE`, l.JobID, o.ComponentID).Scan(&state)
		if errors.Is(e, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if e != nil {
			return e
		}
		if state == "done" {
			return store.ErrConflict
		}
		var options struct {
			Targets       []string `json:"targets"`
			MaxCandidates int      `json:"max_candidates"`
		}
		if e = json.Unmarshal(j.Options, &options); e != nil {
			return e
		}
		if len(options.Targets) == 0 {
			options.Targets = []string{"cpe", "purl"}
		}
		if options.MaxCandidates == 0 {
			options.MaxCandidates = 5
		}
		if len(o.Targets) != len(options.Targets) {
			return fmt.Errorf("%w: all requested targets required", store.ErrInvalid)
		}
		seen := map[string]bool{}
		for _, t := range o.Targets {
			if seen[t.Target] || !oneOf(t.Target, options.Targets...) || !oneOf(t.Decision, "accepted", "review_required", "unresolved") || !validVerification(t.Lookup, t.Target) || len(t.Candidates) > options.MaxCandidates {
				return store.ErrInvalid
			}
			seen[t.Target] = true
			selected := 0
			for _, c := range t.Candidates {
				if c.Value == "" || !oneOf(c.Origin, "sbom", "ai", "nvd", "osv") || !oneOf(c.Scope, "product", "package", "version") || !validVerification(c.Verification, t.Target) || c.Verification.Scope != c.Scope || !oneOf(c.Identity.Status, "strong", "plausible", "ambiguous", "mismatch", "insufficient") || !oneOf(c.VersionStatus, "matched", "unknown", "conflict", "not_checked") {
					return store.ErrInvalid
				}
				if t.Target == "cpe" {
					if _, e = parseCPE(c.Value); e != nil {
						return e
					}
					if c.PURLID != "" {
						return store.ErrInvalid
					}
				} else {
					if _, e = canonicalPURL(c.Value); e != nil {
						return e
					}
					if c.CPENameID != "" {
						return store.ErrInvalid
					}
				}
				if c.Selected {
					selected++
					if c.Verification.Status != "confirmed" || c.Identity.Status != "strong" || (c.Scope == "version" && c.VersionStatus != "matched") {
						return store.ErrInvalid
					}
				}
			}
			if selected > 1 || (t.Decision == "accepted") != (selected == 1) {
				return store.ErrInvalid
			}
		}
		for _, v := range o.Evidence {
			if !store.ValidUUID(v.ID) || !oneOf(v.Source, "nvd", "osv") || !isObject(v.Query) || !json.Valid(v.Snapshot) || v.ObservedAt.IsZero() || !oneOf(v.Scope, "product", "package", "version") || !oneOf(v.MatchKind, "lookup", "cpe_registration", "purl_match", "ecosystem_name_match") {
				return store.ErrInvalid
			}
			canon, e := canonicalJSON(v.Snapshot)
			if e != nil {
				return e
			}
			digest := sha256Hex(canon)
			if v.ResponseSHA256 != "" && v.ResponseSHA256 != digest {
				return store.ErrInvalid
			}
			_, e = tx.Exec(ctx, `INSERT INTO evidence_snapshots(id,job_id,source,source_record_id,reference_url,query,observed_at,response_sha256,scope,match_kind,from_cache,snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, v.ID, l.JobID, v.Source, nullIfEmpty(v.SourceRecordID), nullIfEmpty(v.ReferenceURL), v.Query, v.ObservedAt, digest, v.Scope, v.MatchKind, v.FromCache, v.Snapshot)
			if e != nil {
				return e
			}
		}
		link := func(ids []string, target string, scope string, kind string, candidate string) error {
			source := "osv"
			if target == "cpe" {
				source = "nvd"
			}
			for _, id := range ids {
				var ok bool
				if !store.ValidUUID(id) {
					return store.ErrInvalid
				}
				e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM evidence_snapshots WHERE job_id=$1 AND id=$2 AND source=$3 AND scope=$4 AND ($5='lookup' OR match_kind=$5))`, l.JobID, id, source, scope, kind).Scan(&ok)
				if e != nil {
					return e
				}
				if !ok {
					return store.ErrInvalid
				}
				if candidate == "" {
					_, e = tx.Exec(ctx, `INSERT INTO target_evidence VALUES($1,$2,$3,$4)`, l.JobID, o.ComponentID, target, id)
				} else {
					_, e = tx.Exec(ctx, `INSERT INTO candidate_evidence VALUES($1,$2,$3)`, l.JobID, candidate, id)
				}
				if e != nil {
					return e
				}
			}
			return nil
		}
		for _, t := range o.Targets {
			t.Lookup.EvidenceIDs = emptySlice(t.Lookup.EvidenceIDs)
			_, e = tx.Exec(ctx, `INSERT INTO resolution_targets VALUES($1,$2,$3,$4,$5,$6)`, l.JobID, o.ComponentID, t.Target, t.Decision, mustJSON(emptySlice(t.ReasonCodes)), mustJSON(t.Lookup))
			if e != nil {
				return e
			}
			if e = link(t.Lookup.EvidenceIDs, t.Target, t.Lookup.Scope, t.Lookup.Kind, ""); e != nil {
				return e
			}
			for rank, c := range t.Candidates {
				c.Verification.EvidenceIDs = emptySlice(c.Verification.EvidenceIDs)
				c.Identity.SupportingFields = emptySlice(c.Identity.SupportingFields)
				c.Identity.ConflictingFields = emptySlice(c.Identity.ConflictingFields)
				c.Identity.MissingFields = emptySlice(c.Identity.MissingFields)
				if c.ID == "" {
					c.ID = store.NewID()
				}
				// Referenced dictionary identifiers must describe the exact candidate.
				if c.CPENameID != "" {
					var value string
					e = tx.QueryRow(ctx, `SELECT cpe_name FROM nvd_cpes WHERE cpe_name_id=$1`, c.CPENameID).Scan(&value)
					if e != nil {
						return e
					}
					if value != c.Value {
						return store.ErrInvalid
					}
				}
				if c.PURLID != "" {
					var value string
					e = tx.QueryRow(ctx, `SELECT canonical_purl FROM purls WHERE id=$1`, c.PURLID).Scan(&value)
					if e != nil {
						return e
					}
					parsed, _ := canonicalPURL(c.Value)
					if value != parsed.canonical {
						return store.ErrInvalid
					}
				}
				_, e = tx.Exec(ctx, `INSERT INTO resolution_candidates(id,job_id,component_id,target,rank,value,origin,scope,verification_status,identity_status,version_status,verification,identity_detail,selected,cpe_name_id,purl_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, c.ID, l.JobID, o.ComponentID, t.Target, rank+1, c.Value, c.Origin, c.Scope, c.Verification.Status, c.Identity.Status, c.VersionStatus, mustJSON(c.Verification), mustJSON(c.Identity), c.Selected, nullIfEmpty(c.CPENameID), nullIfEmpty(c.PURLID))
				if e != nil {
					return e
				}
				if e = link(c.Verification.EvidenceIDs, t.Target, c.Scope, c.Verification.Kind, c.ID); e != nil {
					return e
				}
			}
		}
		_, e = tx.Exec(ctx, `UPDATE resolution_components SET state='done',errors=$3 WHERE job_id=$1 AND component_id=$2`, l.JobID, o.ComponentID, mustJSON(emptySlice(o.Errors)))
		if e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `UPDATE resolution_jobs SET processed=processed+1,updated_at=now() WHERE id=$1 AND lease_token=$2 AND lease_until>clock_timestamp() AND deadline>clock_timestamp()`, l.JobID, l.Token)
		if e == nil && tag.RowsAffected() == 0 {
			return store.ErrLeaseLost
		}
		return e
	})
}

// ListResults reads immutable terminal results. Queries are per page, not per
// candidate; ownership is checked before any result/evidence is returned.
func (s *Store) ListResults(ctx context.Context, owner, id string, q store.ResultQuery) (store.ResultPage, error) {
	if !store.ValidUUID(id) {
		return store.ResultPage{}, store.ErrNotFound
	}
	n, e := pageLimit(q.Limit)
	if e != nil {
		return store.ResultPage{}, e
	}
	if q.AfterOrdinal < -1 {
		return store.ResultPage{}, store.ErrInvalid
	}
	var page store.ResultPage
	page.Items = []store.ComponentResult{}
	e = s.inTx(ctx, func(tx pgx.Tx) error {
		j, e := scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM resolution_jobs j WHERE owner_id=$1 AND id=$2 AND expires_at > now() FOR SHARE`, owner, id))
		if errors.Is(e, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if e != nil {
			return e
		}
		if !j.Status.Terminal() {
			return store.ErrNotReady
		}
		page.Job = j
		rows, e := tx.Query(ctx, `SELECT `+componentColumns+` FROM resolution_components c WHERE job_id=$1 AND state='done' AND ordinal>$2 ORDER BY ordinal LIMIT $3`, id, q.AfterOrdinal, n+1)
		if e != nil {
			return e
		}
		comps, e := pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.Component, error) { return scanComponent(r) })
		if e != nil {
			return e
		}
		if len(comps) > n {
			page.HasMore = true
			comps = comps[:n]
			page.NextAfterOrdinal = comps[n-1].Ordinal
		}
		if len(comps) == 0 {
			return nil
		}
		ids := make([]string, len(comps))
		index := map[string]int{}
		for i, c := range comps {
			ids[i] = c.ID
			index[c.ID] = i
			page.Items = append(page.Items, store.ComponentResult{Component: c, Targets: []store.TargetResult{}})
		}
		// Evidence fetched once for this page using links, including reused snapshots.
		evRows, e := tx.Query(ctx, `SELECT DISTINCT e.id::text,e.source,coalesce(e.source_record_id,''),coalesce(e.reference_url,''),e.query,e.observed_at,e.response_sha256,e.scope,e.match_kind,e.from_cache,e.snapshot FROM evidence_snapshots e WHERE e.job_id=$1 AND (EXISTS(SELECT 1 FROM target_evidence t WHERE t.job_id=e.job_id AND t.evidence_id=e.id AND t.component_id=ANY($2)) OR EXISTS(SELECT 1 FROM candidate_evidence ce JOIN resolution_candidates c ON c.job_id=ce.job_id AND c.id=ce.candidate_id WHERE ce.job_id=e.job_id AND ce.evidence_id=e.id AND c.component_id=ANY($2)))`, id, ids)
		if e != nil {
			return e
		}
		evs, e := pgx.CollectRows(evRows, func(r pgx.CollectableRow) (store.Evidence, error) {
			var v store.Evidence
			e := r.Scan(&v.ID, &v.Source, &v.SourceRecordID, &v.ReferenceURL, &v.Query, &v.ObservedAt, &v.ResponseSHA256, &v.Scope, &v.MatchKind, &v.FromCache, &v.Snapshot)
			return v, e
		})
		if e != nil {
			return e
		}
		evMap := map[string]store.Evidence{}
		for _, v := range evs {
			evMap[v.ID] = v
		}
		targets, e := tx.Query(ctx, `SELECT component_id,target,decision,reason_codes,lookup FROM resolution_targets WHERE job_id=$1 AND component_id=ANY($2) ORDER BY component_id,target`, id, ids)
		if e != nil {
			return e
		}
		type rowTarget struct {
			component string
			t         store.TargetResult
		}
		ts, e := pgx.CollectRows(targets, func(r pgx.CollectableRow) (rowTarget, error) {
			var v rowTarget
			var reasons, lookup []byte
			e := r.Scan(&v.component, &v.t.Target, &v.t.Decision, &reasons, &lookup)
			if e != nil {
				return v, e
			}
			if e = json.Unmarshal(reasons, &v.t.ReasonCodes); e != nil {
				return v, e
			}
			e = json.Unmarshal(lookup, &v.t.Lookup)
			return v, e
		})
		if e != nil {
			return e
		}
		targetMap := map[string]*store.TargetResult{}
		for _, v := range ts {
			v.t.Candidates = []store.Candidate{}
			v.t.Evidence = []store.Evidence{}
			for _, eid := range v.t.Lookup.EvidenceIDs {
				v.t.Evidence = append(v.t.Evidence, evMap[eid])
			}
			p := &page.Items[index[v.component]]
			p.Targets = append(p.Targets, v.t)
		}
		for i := range page.Items {
			for k := range page.Items[i].Targets {
				t := &page.Items[i].Targets[k]
				targetMap[page.Items[i].Component.ID+"/"+t.Target] = t
			}
		}
		candidates, e := tx.Query(ctx, `SELECT component_id,target,id::text,value,origin,scope,verification,identity_detail,version_status,selected,coalesce(cpe_name_id::text,''),coalesce(purl_id::text,'') FROM resolution_candidates WHERE job_id=$1 AND component_id=ANY($2) ORDER BY component_id,target,rank`, id, ids)
		if e != nil {
			return e
		}
		type rowCandidate struct {
			component, target string
			c                 store.Candidate
		}
		cs, e := pgx.CollectRows(candidates, func(r pgx.CollectableRow) (rowCandidate, error) {
			var v rowCandidate
			var ver, ident []byte
			e := r.Scan(&v.component, &v.target, &v.c.ID, &v.c.Value, &v.c.Origin, &v.c.Scope, &ver, &ident, &v.c.VersionStatus, &v.c.Selected, &v.c.CPENameID, &v.c.PURLID)
			if e != nil {
				return v, e
			}
			if e = json.Unmarshal(ver, &v.c.Verification); e != nil {
				return v, e
			}
			e = json.Unmarshal(ident, &v.c.Identity)
			return v, e
		})
		if e != nil {
			return e
		}
		for _, v := range cs {
			v.c.Evidence = []store.Evidence{}
			for _, eid := range v.c.Verification.EvidenceIDs {
				v.c.Evidence = append(v.c.Evidence, evMap[eid])
			}
			t := targetMap[v.component+"/"+v.target]
			t.Candidates = append(t.Candidates, v.c)
		}
		return nil
	})
	return page, e
}

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mskmemory/gocpe-ai/db"
	"github.com/mskmemory/gocpe-ai/internal/store"
)

func testStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for disposable PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	p, e := OpenPool(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	// Each test owns a schema; no production data is truncated or dropped.
	schema := "test_" + sha256Hex([]byte(store.NewID()))[:16]
	if _, e = p.Exec(ctx, `CREATE SCHEMA `+schema); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) })
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	tp, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(tp.Close)
	if e = db.Migrate(ctx, tp); e != nil {
		t.Fatal(e)
	}
	return New(tp, Config{}), ctx
}
func require(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func request(owner, key string) store.NewJob {
	return store.NewJob{Owner: owner, Endpoint: store.EndpointResolution, IdempotencyKey: key, Request: json.RawMessage(`{"input":{"name":"demo"}}`), InputKind: "packages", Input: json.RawMessage(`{"name":"demo"}`), Provider: "openai", Model: "test-model", Options: json.RawMessage(`{"targets":["purl"],"max_candidates":5}`), RunMetadata: json.RawMessage(`{"schema_version":"1","usage":{"calls":0}}`), Components: []store.NewComponent{{ID: "c1", Input: json.RawMessage(`{"id":"c1","name":"demo"}`)}}}
}
func claim(t *testing.T, s *Store, ctx context.Context) store.Lease {
	t.Helper()
	l, _, e := s.AcquireJob(ctx, store.AcquireOptions{LeaseDuration: time.Minute, MaxAttempts: 3})
	require(t, e)
	return l
}
func outcome() store.ComponentOutcome {
	now := time.Now().UTC()
	id := store.NewID()
	v := store.Verification{Source: "osv", Kind: "purl_match", Status: "confirmed", Scope: "package", Complete: true, CheckedAt: &now, EvidenceIDs: []string{id}}
	return store.ComponentOutcome{ComponentID: "c1", Evidence: []store.Evidence{{ID: id, Source: "osv", SourceRecordID: "OSV-TEST", Query: json.RawMessage(`{"package":{"purl":"pkg:npm/demo"}}`), Snapshot: json.RawMessage(`{"id":"OSV-TEST","value":"original"}`), ObservedAt: now, Scope: "package", MatchKind: "purl_match"}}, Targets: []store.TargetResult{{Target: "purl", Decision: "accepted", Lookup: v, Candidates: []store.Candidate{{Value: "pkg:npm/demo", Origin: "osv", Scope: "package", Verification: v, Identity: store.Identity{Status: "strong", SupportingFields: []string{"ecosystem", "name"}}, VersionStatus: "unknown", Selected: true}}}}}
}
func TestMigrations(t *testing.T) {
	s, ctx := testStore(t)
	var wg sync.WaitGroup
	es := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); es <- db.Migrate(ctx, s.pool) }()
	}
	wg.Wait()
	close(es)
	for e := range es {
		require(t, e)
	}
	a, p, e := db.Status(ctx, s.pool)
	require(t, e)
	if len(a) != 1 || p != 0 {
		t.Fatalf("history %v pending %d", a, p)
	}
	require(t, db.Rollback(ctx, s.pool, 1))
	require(t, db.Migrate(ctx, s.pool))
	_, e = s.pool.Exec(ctx, `UPDATE schema_migrations SET checksum='invalid'`)
	require(t, e)
	if e = db.Migrate(ctx, s.pool); !errors.Is(e, db.ErrHistoryMismatch) {
		t.Fatalf("expected checksum rejection: %v", e)
	}
}
func TestDictionary(t *testing.T) {
	s, ctx := testStore(t)
	now := time.Now().UTC()
	c := store.CPERecord{NameID: store.NewID(), Name: `cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*`, SourceModifiedAt: now, FetchedAt: now, Raw: json.RawMessage(`{"marker":"new"}`), Titles: []string{"Apache Log4j"}, ReplacedBy: []string{store.NewID()}}
	r, e := s.UpsertCPE(ctx, c)
	require(t, e)
	if !r.Applied {
		t.Fatal("not applied")
	}
	c.SourceModifiedAt = now.Add(-time.Hour)
	c.Deprecated = true
	r, e = s.UpsertCPE(ctx, c)
	require(t, e)
	if r.Applied {
		t.Fatal("stale applied")
	}
	got, e := s.GetCPE(ctx, c.NameID)
	require(t, e)
	if got.Deprecated || got.Attributes["update"] != "*" || got.Product != "log4j" || len(got.ReplacedBy) != 1 {
		t.Fatalf("CPE %+v", got)
	}
	cp, e := s.SearchCPEs(ctx, store.CPEQuery{Vendor: "apache", Query: "Log4j"})
	require(t, e)
	if len(cp.Items) != 1 {
		t.Fatal(cp)
	}
	// PURL storage alone is not a positive external observation.
	p, e := s.EnsurePURL(ctx, "pkg:npm/demo?z=last&a=first")
	require(t, e)
	p2, e := s.EnsurePURL(ctx, "pkg:npm/demo?a=first&z=last")
	require(t, e)
	if p.ID != p2.ID {
		t.Fatal("canonical duplicate")
	}
	ps, e := s.SearchPURLs(ctx, store.PURLQuery{})
	require(t, e)
	if len(ps.Items) != 0 {
		t.Fatal("unconfirmed PURL visible")
	}
	o := store.OSVRecord{ID: "OSV-TEST", ModifiedAt: now, FetchedAt: now, Raw: json.RawMessage(`{"id":"OSV-TEST"}`), Affected: []store.OSVAffected{{Index: 0, Ecosystem: "npm", Name: "demo", PURL: p.Canonical, RawPURL: p.Canonical, Mapping: store.PURLExplicit, Affected: json.RawMessage(`{"package":{"name":"demo"}}`)}}}
	_, e = s.UpsertOSV(ctx, o)
	require(t, e)
	ps, e = s.SearchPURLs(ctx, store.PURLQuery{Name: "demo"})
	require(t, e)
	if len(ps.Items) != 1 || len(ps.Items[0].OSVRecordIDs) != 1 {
		t.Fatal(ps)
	}
	o.ModifiedAt = now.Add(-time.Hour)
	o.Affected = nil
	r, e = s.UpsertOSV(ctx, o)
	require(t, e)
	if r.Applied {
		t.Fatal("stale OSV accepted")
	}
	fetched, e := s.GetOSV(ctx, o.ID)
	require(t, e)
	if len(fetched.Affected) != 1 {
		t.Fatal(fetched)
	}
	o.ModifiedAt = now.Add(time.Hour)
	o.WithdrawnAt = &now
	_, e = s.UpsertOSV(ctx, o)
	require(t, e)
	ps, e = s.SearchPURLs(ctx, store.PURLQuery{})
	require(t, e)
	if len(ps.Items) != 0 {
		t.Fatal("withdrawn visible")
	}
}
func TestConcurrentIdempotency(t *testing.T) {
	s, ctx := testStore(t)
	var wg sync.WaitGroup
	type result struct {
		j       store.Job
		created bool
		e       error
	}
	ch := make(chan result, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); j, c, e := s.CreateJob(ctx, request("owner", "same")); ch <- result{j, c, e} }()
	}
	wg.Wait()
	close(ch)
	id := ""
	created := 0
	for r := range ch {
		require(t, r.e)
		if id == "" {
			id = r.j.ID
		}
		if r.j.ID != id {
			t.Fatal("duplicate jobs")
		}
		if r.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created %d", created)
	}
	nj := request("owner", "same")
	nj.Request = json.RawMessage(`{"input":{"name":"different"}}`)
	_, _, e := s.CreateJob(ctx, nj)
	if !errors.Is(e, store.ErrIdempotencyConflict) {
		t.Fatal(e)
	}
	nj = request("owner", "same")
	nj.Endpoint = store.EndpointPackageSearch
	_, _, e = s.CreateJob(ctx, nj)
	if !errors.Is(e, store.ErrIdempotencyConflict) {
		t.Fatal(e)
	}
	_, e = s.GetJob(ctx, "other", id)
	if !errors.Is(e, store.ErrNotFound) {
		t.Fatal(e)
	}
	_, e = s.CancelJob(ctx, "other", id)
	if !errors.Is(e, store.ErrNotFound) {
		t.Fatal(e)
	}
	var count int
	require(t, s.pool.QueryRow(ctx, `SELECT count(*) FROM resolution_jobs`).Scan(&count))
	if count != 1 {
		t.Fatal(count)
	}
}
func TestOutcomeLeaseAndEvidence(t *testing.T) {
	s, ctx := testStore(t)
	j, _, e := s.CreateJob(ctx, request("owner", ""))
	require(t, e)
	_, e = s.ListResults(ctx, "owner", j.ID, store.ResultQuery{AfterOrdinal: -1})
	if !errors.Is(e, store.ErrNotReady) {
		t.Fatal(e)
	}
	l := claim(t, s, ctx)
	cs, e := s.NextComponents(ctx, l, 10)
	require(t, e)
	if len(cs) != 1 {
		t.Fatal(cs)
	}
	// Fault injected into disposable schema, no sleep/race with wall clock.
	_, e = s.pool.Exec(ctx, `UPDATE resolution_jobs SET lease_until=now()-interval '1 second' WHERE id=$1`, j.ID)
	require(t, e)
	if e = s.CompleteComponent(ctx, l, outcome()); !errors.Is(e, store.ErrLeaseLost) {
		t.Fatal(e)
	}
	next := claim(t, s, ctx)
	if next.Token == l.Token {
		t.Fatal("lease not fenced")
	}
	if _, e = s.Heartbeat(ctx, l, time.Minute); !errors.Is(e, store.ErrLeaseLost) {
		t.Fatal(e)
	}
	o := outcome()
	require(t, s.CompleteComponent(ctx, next, o))
	if e = s.CompleteComponent(ctx, next, o); !errors.Is(e, store.ErrConflict) {
		t.Fatal(e)
	}
	require(t, s.AddUsage(ctx, next, store.Usage{Calls: 1, InputTokens: 5}))
	done, e := s.FinishJob(ctx, next, store.StatusCompleted, nil)
	require(t, e)
	if done.Processed != 1 {
		t.Fatal(done)
	}
	page, e := s.ListResults(ctx, "owner", j.ID, store.ResultQuery{AfterOrdinal: -1})
	require(t, e)
	if len(page.Items) != 1 || len(page.Items[0].Targets[0].Candidates[0].Evidence) != 1 {
		t.Fatalf("page %+v", page)
	}
	before := string(page.Items[0].Targets[0].Candidates[0].Evidence[0].Snapshot)
	_, e = s.UpsertOSV(ctx, store.OSVRecord{ID: "OSV-TEST", ModifiedAt: time.Now(), FetchedAt: time.Now(), Raw: json.RawMessage(`{"marker":"changed"}`)})
	require(t, e)
	page, e = s.ListResults(ctx, "owner", j.ID, store.ResultQuery{AfterOrdinal: -1})
	require(t, e)
	if string(page.Items[0].Targets[0].Candidates[0].Evidence[0].Snapshot) != before {
		t.Fatal("evidence mutated")
	}
	if e = s.AddUsage(ctx, next, store.Usage{Calls: 1}); !errors.Is(e, store.ErrLeaseLost) {
		t.Fatal(e)
	}
	_, e = s.ListResults(ctx, "other", j.ID, store.ResultQuery{AfterOrdinal: -1})
	if !errors.Is(e, store.ErrNotFound) {
		t.Fatal(e)
	}
}
func TestOutcomeAtomicRollback(t *testing.T) {
	s, ctx := testStore(t)
	j, _, e := s.CreateJob(ctx, request("owner", ""))
	require(t, e)
	l := claim(t, s, ctx)
	o := outcome()
	o.Targets[0].Candidates[0].Verification.EvidenceIDs = []string{store.NewID()}
	if e = s.CompleteComponent(ctx, l, o); !errors.Is(e, store.ErrInvalid) {
		t.Fatal(e)
	}
	var count int
	require(t, s.pool.QueryRow(ctx, `SELECT count(*) FROM evidence_snapshots`).Scan(&count))
	if count != 0 {
		t.Fatal("partial evidence committed")
	}
	j, e = s.GetJob(ctx, "owner", j.ID)
	require(t, e)
	if j.Processed != 0 {
		t.Fatal(j)
	}
	require(t, s.CompleteComponent(ctx, l, outcome()))
}
func TestCancelDeadlineAndPurge(t *testing.T) {
	s, ctx := testStore(t)
	j, _, e := s.CreateJob(ctx, request("owner", "key"))
	require(t, e)
	cancelled, e := s.CancelJob(ctx, "owner", j.ID)
	require(t, e)
	if cancelled.Status != store.StatusCancelled {
		t.Fatal(cancelled)
	}
	_, e = s.ListResults(ctx, "owner", j.ID, store.ResultQuery{AfterOrdinal: -1})
	require(t, e)
	j2, _, e := s.CreateJob(ctx, request("owner", ""))
	require(t, e)
	l := claim(t, s, ctx)
	_, e = s.CancelJob(ctx, "owner", j2.ID)
	require(t, e)
	if e = s.CompleteComponent(ctx, l, outcome()); !errors.Is(e, store.ErrLeaseLost) {
		t.Fatal(e)
	}
	done, e := s.FinishJob(ctx, l, store.StatusCompleted, nil)
	require(t, e)
	if done.Status != store.StatusCancelled {
		t.Fatal(done)
	}
	overdue, _, e := s.CreateJob(ctx, request("owner", ""))
	require(t, e)
	_, e = s.pool.Exec(ctx, `UPDATE resolution_jobs SET created_at=now()-interval '2 hours',deadline=now()-interval '1 hour' WHERE id=$1`, overdue.ID)
	require(t, e)
	reaped, e := s.ReapExpired(ctx, 3)
	require(t, e)
	if reaped.Failed != 1 {
		t.Fatal(reaped)
	}
	_, e = s.pool.Exec(ctx, `UPDATE idempotency_keys SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour'`)
	require(t, e)
	_, e = s.pool.Exec(ctx, `UPDATE resolution_jobs SET created_at=now()-interval '3 days',deadline=now()-interval '2 days',expires_at=now()-interval '1 day'`)
	require(t, e)
	p, e := s.PurgeExpired(ctx, 100)
	require(t, e)
	if p.Jobs != 3 || p.IdempotencyKeys != 1 {
		t.Fatal(p)
	}
}
func TestConstraintEnforcement(t *testing.T) {
	s, ctx := testStore(t)
	_, e := s.pool.Exec(ctx, `INSERT INTO purls(id,canonical_purl,purl_sha256,normalization_version,type,name) VALUES($1,'pkg:npm/demo','bad','1','npm','demo')`, store.NewID())
	if e == nil {
		t.Fatal("bad hash accepted")
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO nvd_cpe_replacements VALUES($1,$2)`, store.NewID(), store.NewID())
	if e == nil {
		t.Fatal("missing foreign key accepted")
	}
	j, _, e := s.CreateJob(ctx, request("owner", ""))
	require(t, e)
	l := claim(t, s, ctx)
	require(t, s.CompleteComponent(ctx, l, outcome()))
	var cid string
	require(t, s.pool.QueryRow(ctx, `SELECT id::text FROM resolution_candidates WHERE job_id=$1`, j.ID).Scan(&cid))
	_, e = s.pool.Exec(ctx, `UPDATE resolution_candidates SET verification_status='no_evidence' WHERE id=$1`, cid)
	if e == nil {
		t.Fatal("unverified selected accepted")
	}
	_, e = s.pool.Exec(ctx, `INSERT INTO resolution_candidates SELECT $2::uuid,job_id,component_id,target,2,value,origin,scope,verification_status,identity_status,version_status,verification,identity_detail,selected,cpe_name_id,purl_id FROM resolution_candidates WHERE id=$1`, cid, store.NewID())
	if e == nil {
		t.Fatal("two selected accepted")
	}
}

func TestSchemaSnapshotMatchesMigrations(t *testing.T) {
	s, ctx := testStore(t)
	catalog := func() string {
		t.Helper()
		var result string
		require(t, s.pool.QueryRow(ctx, `SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]')::text FROM (
 SELECT jsonb_build_object('kind','column','table',c.relname,'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'notnull',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)) AS v
 FROM pg_class c JOIN pg_namespace ns ON c.relnamespace=ns.oid JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE ns.nspname=current_schema() AND c.relkind='r' AND c.relname <> 'schema_migrations' AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT jsonb_build_object('kind','constraint','name',co.conname,'def',pg_get_constraintdef(co.oid)) FROM pg_constraint co JOIN pg_namespace ns ON co.connamespace=ns.oid WHERE ns.nspname=current_schema() AND co.conrelid<>coalesce(to_regclass('schema_migrations'),0)
 UNION ALL SELECT jsonb_build_object('kind','index','name',indexname,'def',indexdef) FROM pg_indexes WHERE schemaname=current_schema() AND tablename <> 'schema_migrations') rows`).Scan(&result))
		return result
	}
	before := catalog()
	require(t, db.Rollback(ctx, s.pool, 1))
	snapshot, e := os.ReadFile("../../../db/schema.sql")
	require(t, e)
	_, e = s.pool.Exec(ctx, string(snapshot))
	require(t, e)
	if got := catalog(); got != before {
		t.Fatal("schema snapshot differs from migrations")
	}
}

func TestResultPagination(t *testing.T) {
	s, ctx := testStore(t)
	nj := request("owner", "")
	nj.Components = append(nj.Components, store.NewComponent{ID: "c2", Input: json.RawMessage(`{"id":"c2","name":"other"}`)})
	j, _, e := s.CreateJob(ctx, nj)
	require(t, e)
	l := claim(t, s, ctx)
	require(t, s.CompleteComponent(ctx, l, outcome()))
	o := outcome()
	o.ComponentID = "c2"
	require(t, s.CompleteComponent(ctx, l, o))
	_, e = s.FinishJob(ctx, l, store.StatusCompleted, nil)
	require(t, e)
	first, e := s.ListResults(ctx, "owner", j.ID, store.ResultQuery{AfterOrdinal: -1, Limit: 1})
	require(t, e)
	if !first.HasMore || first.Items[0].Component.ID != "c1" {
		t.Fatal(first)
	}
	second, e := s.ListResults(ctx, "owner", j.ID, store.ResultQuery{AfterOrdinal: first.NextAfterOrdinal, Limit: 1})
	require(t, e)
	if second.HasMore || second.Items[0].Component.ID != "c2" {
		t.Fatal(second)
	}
}

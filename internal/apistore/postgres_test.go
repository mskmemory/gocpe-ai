package apistore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mskmemory/gocpe-ai/db"
	"github.com/mskmemory/gocpe-ai/internal/apistore"
	"github.com/mskmemory/gocpe-ai/internal/httpapi"
	"github.com/mskmemory/gocpe-ai/internal/service"
	"github.com/mskmemory/gocpe-ai/internal/store"
	"github.com/mskmemory/gocpe-ai/internal/store/postgres"
)

const tokenA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const tokenB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const search = `{"name":"demo","vendor":"Example","options":{"provider":"openai","model":"integration-model","targets":["purl"]}}`

type fixture struct {
	server  *httptest.Server
	repo    *postgres.Store
	adapter *apistore.Postgres
	pool    *pgxpool.Pool
}

func setup(t *testing.T) fixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI_REQUIRE_DB_TESTS") == "1" {
			t.Fatal("TEST_DATABASE_URL required")
		}
		t.Skip("set TEST_DATABASE_URL for HTTP + PostgreSQL integration")
	}
	ctx := context.Background()
	admin, e := postgres.OpenPool(ctx, dsn)
	must(t, e)
	t.Cleanup(admin.Close)
	schema := "http_" + strings.ReplaceAll(store.NewID(), "-", "")
	_, e = admin.Exec(ctx, `CREATE SCHEMA `+schema)
	must(t, e)
	t.Cleanup(func() {
		_, e := admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		if e != nil {
			t.Error(e)
		}
	})
	cfg, e := pgxpool.ParseConfig(dsn)
	must(t, e)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	must(t, e)
	t.Cleanup(pool.Close)
	must(t, db.Migrate(ctx, pool))
	repo := postgres.New(pool, postgres.Config{})
	a := &apistore.Postgres{Repository: repo, Ready: func(context.Context) bool { return true }}
	svc, e := service.New(service.Config{Store: a, Providers: map[service.Provider][]string{"openai": {"integration-model"}}, CursorKey: []byte(strings.Repeat("k", 32))})
	must(t, e)
	auth, e := httpapi.NewStaticAuth(map[string]httpapi.Principal{tokenA: {OwnerID: "alice", Read: true, Write: true}, tokenB: {OwnerID: "bob", Read: true, Write: true}})
	must(t, e)
	h, e := httpapi.New(svc, auth)
	must(t, e)
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return fixture{server, repo, a, pool}
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func (f fixture) request(method, path, body, token, key string) (int, []byte, error) {
	r, e := http.NewRequest(method, f.server.URL+path, strings.NewReader(body))
	if e != nil {
		return 0, nil, e
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	res, e := client.Do(r)
	if e != nil {
		return 0, nil, e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(res.Body)
	return res.StatusCode, b, e
}
func (f fixture) check(t *testing.T, method, path, body, token, key string, want int) []byte {
	t.Helper()
	status, b, e := f.request(method, path, body, token, key)
	must(t, e)
	if status != want {
		t.Fatalf("%s %s: got %d want %d: %s", method, path, status, want, b)
	}
	return b
}
func jobID(t *testing.T, b []byte) string {
	t.Helper()
	var j service.Job
	must(t, json.Unmarshal(b, &j))
	if j.ID == "" {
		t.Fatalf("missing job: %s", b)
	}
	return j.ID
}
func TestHTTPPostgresAdmissionAndCancel(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.check(t, "GET", "/v1/providers", "", tokenA, "", 200)
	f.check(t, "GET", "/v1/cpes", "", "", "", 401)
	id := jobID(t, f.check(t, "POST", "/v1/package-searches", search, tokenA, "shared", 202))
	if replay := jobID(t, f.check(t, "POST", "/v1/package-searches", search, tokenA, "shared", 202)); replay != id {
		t.Fatal("replay created another job")
	}
	f.check(t, "POST", "/v1/package-searches", strings.Replace(search, "demo", "other", 1), tokenA, "shared", 409)
	f.check(t, "GET", "/v1/resolutions/"+id, "", tokenB, "", 404)
	f.check(t, "POST", "/v1/resolutions/"+id+"/cancel", "", tokenB, "", 404)
	f.check(t, "GET", "/v1/resolutions/"+id+"/results", "", tokenA, "", 409)
	f.check(t, "POST", "/v1/resolutions/"+id+"/cancel", "", tokenA, "", 202)
	f.check(t, "POST", "/v1/resolutions/"+id+"/cancel", "", tokenA, "", 200)
	b := f.check(t, "GET", "/v1/resolutions/"+id+"/results", "", tokenA, "", 200)
	if !bytes.Contains(b, []byte(`"items":[]`)) {
		t.Fatalf("cancelled empty results: %s", b)
	}
	var count int
	must(t, f.pool.QueryRow(ctx, "SELECT count(*) FROM resolution_jobs").Scan(&count))
	if count != 1 {
		t.Fatal(count)
	}
	f.adapter.Ready = func(context.Context) bool { return false }
	f.check(t, "POST", "/v1/package-searches", search, tokenA, "shared", 202)
	f.check(t, "POST", "/v1/package-searches", search, tokenA, "new", 503)
	_, e := f.pool.Exec(ctx, "UPDATE resolution_jobs SET created_at=now()-interval '3 days',deadline=now()-interval '2 days',expires_at=now()-interval '1 day' WHERE id=$1", id)
	must(t, e)
	f.check(t, "GET", "/v1/resolutions/"+id, "", tokenA, "", 404)
	f.check(t, "POST", "/v1/resolutions/"+id+"/cancel", "", tokenA, "", 404)
}
func TestHTTPPostgresConcurrentIdempotency(t *testing.T) {
	f := setup(t)
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, b, e := f.request("POST", "/v1/package-searches", search, tokenA, "concurrent")
			if e != nil {
				errs <- e
				return
			}
			if status != 202 {
				errs <- &statusError{status, string(b)}
				return
			}
			var j service.Job
			e = json.Unmarshal(b, &j)
			if e != nil {
				errs <- e
				return
			}
			ids <- j.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	var id string
	for v := range ids {
		if id != "" && v != id {
			t.Error("multiple jobs")
		}
		id = v
	}
	var n int
	must(t, f.pool.QueryRow(context.Background(), "SELECT count(*) FROM resolution_jobs").Scan(&n))
	if n != 1 {
		t.Fatal(n)
	}
}

type statusError struct {
	status int
	body   string
}

func (e *statusError) Error() string { return e.body }
func TestHTTPPostgresWorkerResults(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	body := `{"input":{"kind":"packages","packages":[{"id":"c1","name":"demo"},{"id":"c2","name":"other"}]},"options":{"provider":"openai","model":"integration-model","targets":["purl"]}}`
	id := jobID(t, f.check(t, "POST", "/v1/resolutions", body, tokenA, "batch", 202))
	lease, j, e := f.repo.AcquireJob(ctx, store.AcquireOptions{LeaseDuration: time.Minute, MaxAttempts: 3})
	must(t, e)
	if j.ID != id {
		t.Fatal("wrong lease")
	}
	comps, e := f.repo.NextComponents(ctx, lease, 2)
	must(t, e)
	if len(comps) != 2 {
		t.Fatal(len(comps))
	}
	for _, c := range comps {
		now := time.Now().UTC()
		evID := store.NewID()
		v := store.Verification{Source: "osv", Kind: "purl_match", Status: "confirmed", Scope: "package", Complete: true, CheckedAt: &now, EvidenceIDs: []string{evID}}
		ev := store.Evidence{ID: evID, Source: "osv", SourceRecordID: "OSV-INTEGRATION", Query: json.RawMessage(`{"package":{"purl":"pkg:npm/demo"}}`), Snapshot: json.RawMessage(`{"id":"OSV-INTEGRATION"}`), ObservedAt: now, Scope: "package", MatchKind: "purl_match"}
		must(t, f.repo.CompleteComponent(ctx, lease, store.ComponentOutcome{ComponentID: c.ID, Evidence: []store.Evidence{ev}, Targets: []store.TargetResult{{Target: "purl", Decision: "review_required", Lookup: v, ReasonCodes: []string{"VERSION_UNKNOWN"}, Candidates: []store.Candidate{{Value: "pkg:npm/demo", Origin: "osv", Scope: "package", Verification: v, Identity: store.Identity{Status: "plausible"}, VersionStatus: "unknown"}}}}}))
	}
	_, e = f.repo.FinishJob(ctx, lease, store.StatusCompleted, nil)
	must(t, e)
	first := f.check(t, "GET", "/v1/resolutions/"+id+"/results?limit=1", "", tokenA, "", 200)
	var page service.ResultPage
	must(t, json.Unmarshal(first, &page))
	if len(page.Items) != 1 || page.NextCursor == "" || page.Items[0].PURL == nil || len(page.Items[0].PURL.Candidates[0].Evidence) != 1 {
		t.Fatalf("page: %s", first)
	}
	second := f.check(t, "GET", "/v1/resolutions/"+id+"/results?limit=1&cursor="+page.NextCursor, "", tokenA, "", 200)
	page = service.ResultPage{}
	must(t, json.Unmarshal(second, &page))
	if len(page.Items) != 1 || page.Items[0].ComponentID != "c2" || page.NextCursor != "" {
		t.Fatalf("page: %s", second)
	}
	f.check(t, "GET", "/v1/resolutions/"+id+"/results?cursor=invalid", "", tokenA, "", 400)
	// Inspect DB independently of the adapter, rather than trusting only HTTP.
	var processed int
	must(t, f.pool.QueryRow(ctx, "SELECT processed FROM resolution_jobs WHERE id=$1", id).Scan(&processed))
	if processed != 2 {
		t.Fatal(processed)
	}
}
func TestHTTPPostgresDictionaries(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// 201 rows exercises service Limit+1 against persistence's maximum 200.
	for range 201 {
		_, e := f.repo.UpsertCPE(ctx, store.CPERecord{NameID: store.NewID(), Name: "cpe:2.3:a:example:demo:" + store.NewID() + ":*:*:*:*:*:*:*", SourceModifiedAt: now, FetchedAt: now, Raw: json.RawMessage(`{}`)})
		must(t, e)
	}
	b := f.check(t, "GET", "/v1/cpes?vendor=example&limit=200", "", tokenA, "", 200)
	var page service.CPEPage
	must(t, json.Unmarshal(b, &page))
	if len(page.Items) != 200 || page.NextCursor == "" {
		t.Fatalf("bad dictionary paging: %s", b)
	}
	f.check(t, "GET", "/v1/cpes?vendor=other&cursor="+page.NextCursor, "", tokenA, "", 400)
	b = f.check(t, "GET", "/v1/cpes?vendor=example&limit=200&cursor="+page.NextCursor, "", tokenA, "", 200)
	must(t, json.Unmarshal(b, &page))
	if len(page.Items) != 1 {
		t.Fatal(len(page.Items))
	}
	rec := store.OSVRecord{ID: "OSV-HTTP", ModifiedAt: now, FetchedAt: now, Raw: json.RawMessage(`{}`), Affected: []store.OSVAffected{{Index: 0, Ecosystem: "npm", Name: "demo", PURL: "pkg:npm/demo", RawPURL: "pkg:npm/demo", Mapping: store.PURLExplicit, Affected: json.RawMessage(`{}`)}}}
	_, e := f.repo.UpsertOSV(ctx, rec)
	must(t, e)
	b = f.check(t, "GET", "/v1/purls?type=npm&name=demo", "", tokenA, "", 200)
	var p service.PURLPage
	must(t, json.Unmarshal(b, &p))
	if len(p.Items) != 1 || p.Items[0].CanonicalPURL != "pkg:npm/demo" {
		t.Fatalf("purl: %s", b)
	}
	withdrawn := now.Add(time.Minute)
	rec.ModifiedAt = withdrawn
	rec.WithdrawnAt = &withdrawn
	_, e = f.repo.UpsertOSV(ctx, rec)
	must(t, e)
	b = f.check(t, "GET", "/v1/purls?name=demo", "", tokenA, "", 200)
	must(t, json.Unmarshal(b, &p))
	if len(p.Items) != 0 {
		t.Fatal("withdrawn still visible")
	}
}

func TestHTTPPostgresSBOMAndValidation(t *testing.T) {
	f := setup(t)
	body := `{"input":{"kind":"sbom","format":"cyclonedx","document":{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","bom-ref":"lib-1","name":"demo","supplier":{"name":"Example"}}]}},"options":{"provider":"openai","model":"integration-model","targets":["cpe"]}}`
	id := jobID(t, f.check(t, "POST", "/v1/resolutions", body, tokenA, "sbom", 202))
	var kind, component string
	must(t, f.pool.QueryRow(context.Background(), "SELECT input_kind FROM resolution_jobs WHERE id=$1", id).Scan(&kind))
	must(t, f.pool.QueryRow(context.Background(), "SELECT component_id FROM resolution_components WHERE job_id=$1", id).Scan(&component))
	if kind != "sbom" || component != "lib-1" {
		t.Fatalf("%s %s", kind, component)
	}
	f.check(t, "POST", "/v1/package-searches", `{"name":"","vendor":"Example","options":{"provider":"openai","model":"integration-model"}}`, tokenA, "invalid", 422)
	var n int
	must(t, f.pool.QueryRow(context.Background(), "SELECT count(*) FROM resolution_jobs").Scan(&n))
	if n != 1 {
		t.Fatal("invalid input persisted")
	}
	lease, _, e := f.repo.AcquireJob(context.Background(), store.AcquireOptions{LeaseDuration: time.Minute, MaxAttempts: 3})
	must(t, e)
	f.check(t, "POST", "/v1/resolutions/"+id+"/cancel", "", tokenA, "", 202)
	f.check(t, "POST", "/v1/resolutions/"+id+"/cancel", "", tokenA, "", 202)
	_, e = f.repo.FinishJob(context.Background(), lease, store.StatusCompleted, nil)
	must(t, e)
	b := f.check(t, "GET", "/v1/resolutions/"+id, "", tokenA, "", 200)
	var j service.Job
	must(t, json.Unmarshal(b, &j))
	if j.Status != "cancelled" {
		t.Fatal(j.Status)
	}
}
func TestHTTPPostgresDatabaseFailure(t *testing.T) {
	f := setup(t)
	f.pool.Close()
	f.check(t, "GET", "/v1/cpes", "", tokenA, "", 503)
	f.check(t, "GET", "/v1/purls", "", tokenA, "", 503)
	f.check(t, "POST", "/v1/package-searches", search, tokenA, "", 503)
}

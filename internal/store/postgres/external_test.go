package postgres

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"github.com/mskmemory/gocpe-ai/internal/nvd"
	"github.com/mskmemory/gocpe-ai/internal/osv"
	"github.com/mskmemory/gocpe-ai/internal/resolve"
	"github.com/mskmemory/gocpe-ai/internal/store"
	"github.com/mskmemory/gocpe-ai/internal/syncdata"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const externalCPE = `cpe:2.3:a:example:demo:1.0:*:*:*:*:*:*:*`
const externalProduct = `{"cpe":{"cpeName":"` + externalCPE + `","cpeNameId":"00000000-0000-4000-8000-000000000001","lastModified":"2025-01-01T00:00:00.000","deprecated":true,"deprecatedBy":[{"cpeNameId":"00000000-0000-4000-8000-000000000002"}],"extra":{"retained":true}}}`
const externalOSV = `{"id":"OSV-TEST","modified":"2025-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"demo","purl":"pkg:npm/demo"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}],"extra":{"retained":true}}`

func TestExternalHTTPToDictionaryAndOutcome(t *testing.T) {
	s, ctx := testStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprintf(w, `{"startIndex":0,"resultsPerPage":1,"totalResults":1,"products":[%s]}`, externalProduct)
		} else {
			fmt.Fprintf(w, `{"vulns":[%s]}`, externalOSV)
		}
	}))
	defer server.Close()
	external := resolve.External{NVD: nvd.New(nvd.Config{Endpoint: server.URL}), OSV: osv.New(osv.Config{Endpoint: server.URL}), Dictionary: s}
	c, e := external.CPE(ctx, nvd.Query{Keyword: "demo"}, externalCPE)
	require(t, e)
	p, e := external.PURL(ctx, "pkg:npm/demo@1.0?arch=x86#src")
	require(t, e)
	if p.Target.Candidates[0].Verification.Status != "confirmed" || p.Target.Candidates[0].Identity.Status != "insufficient" || p.Target.Candidates[0].Selected {
		t.Fatal(p)
	}
	cpes, e := s.SearchCPEs(ctx, store.CPEQuery{Product: "demo"})
	require(t, e)
	if len(cpes.Items) != 1 || !cpes.Items[0].Deprecated {
		t.Fatal(cpes)
	}
	purls, e := s.SearchPURLs(ctx, store.PURLQuery{Name: "demo"})
	require(t, e)
	if len(purls.Items) != 1 || purls.Items[0].Canonical != "pkg:npm/demo" {
		t.Fatal(purls)
	}
	rec, e := s.GetOSV(ctx, "OSV-TEST")
	require(t, e)
	if !strings.Contains(string(rec.Raw), "retained") || len(rec.Affected) != 1 {
		t.Fatal(rec)
	}
	input := request("external", "key")
	input.Options = json.RawMessage(`{"targets":["cpe","purl"],"max_candidates":5}`)
	job, _, e := s.CreateJob(ctx, input)
	require(t, e)
	lease := claim(t, s, ctx)
	evidence := append(c.Evidence, p.Evidence...)
	require(t, s.CompleteComponent(ctx, lease, store.ComponentOutcome{ComponentID: "c1", Targets: []store.TargetResult{c.Target, p.Target}, Evidence: evidence}))
	_, e = s.FinishJob(ctx, lease, store.StatusCompleted, nil)
	require(t, e)
	result, e := s.ListResults(ctx, "external", job.ID, store.ResultQuery{AfterOrdinal: -1})
	require(t, e)
	if len(result.Items) != 1 || len(result.Items[0].Targets) != 2 {
		t.Fatal(result)
	}
	for _, target := range result.Items[0].Targets {
		if len(target.Candidates) != 1 || len(target.Candidates[0].Evidence) == 0 || target.Candidates[0].Evidence[0].ResponseSHA256 == "" {
			t.Fatal(target)
		}
	}
}
func TestExternalNoEvidenceAndIncomplete(t *testing.T) {
	s, ctx := testStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{}`) }))
	defer server.Close()
	e := resolve.External{OSV: osv.New(osv.Config{Endpoint: server.URL}), Dictionary: s}
	r, err := e.PURL(ctx, "pkg:npm/demo")
	require(t, err)
	if r.Target.Lookup.Status != "no_evidence" || r.Target.Decision != "unresolved" {
		t.Fatal(r)
	}
	r, err = e.PURL(ctx, "pkg:generic/demo")
	if !errors.Is(err, lookup.ErrUnsupported) || r.Target.Lookup.Status != "unsupported" {
		t.Fatal(r, err)
	}
}
func makeArchive(t *testing.T, records ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "all.zip")
	f, e := os.Create(path)
	require(t, e)
	z := zip.NewWriter(f)
	for i, r := range records {
		w, e := z.Create(fmt.Sprintf("%d.json", i))
		require(t, e)
		_, e = w.Write([]byte(r))
		require(t, e)
	}
	require(t, z.Close())
	require(t, f.Close())
	return path
}
func TestFullSyncResume(t *testing.T) {
	s, ctx := testStore(t)
	archive := makeArchive(t, externalOSV, `{"id":"WITHDRAWN","modified":"2025-01-01T00:00:00Z","withdrawn":"2025-01-02T00:00:00Z"}`, `{"id":"OTHER","modified":"2025-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Unknown","name":"thing"}}]}`)
	if e := syncdata.OSV(ctx, s, syncdata.OSVConfig{Archive: archive, MaxRecords: 1}); !errors.Is(e, lookup.ErrPageLimit) {
		t.Fatal(e)
	}
	var watermark *time.Time
	var status string
	require(t, s.pool.QueryRow(ctx, `SELECT watermark,status FROM source_sync_state WHERE source='osv'`).Scan(&watermark, &status))
	if watermark != nil || status != "failed" {
		t.Fatal(status, watermark)
	}
	require(t, syncdata.OSV(ctx, s, syncdata.OSVConfig{Archive: archive}))
	r, e := s.GetOSV(ctx, "WITHDRAWN")
	require(t, e)
	if r.WithdrawnAt == nil {
		t.Fatal(r)
	}
	r, e = s.GetOSV(ctx, "OTHER")
	require(t, e)
	if r.Affected[0].Mapping != store.PURLUnavailable {
		t.Fatal(r)
	}
	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := r.URL.Query().Get("startIndex")
		offsets = append(offsets, start)
		fmt.Fprintf(w, `{"startIndex":%s,"resultsPerPage":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2025-000%s","lastModified":"2025-01-01T00:00:00.000","metrics":{"retained":true}}}]}`, start, start)
	}))
	defer server.Close()
	cfg := syncdata.NVDConfig{BaseURL: server.URL, MaxPages: 1, Interval: time.Nanosecond}
	if e = syncdata.NVD(ctx, s, cfg, "cve"); !errors.Is(e, lookup.ErrPageLimit) {
		t.Fatal(e)
	}
	require(t, syncdata.NVD(ctx, s, cfg, "cve"))
	if fmt.Sprint(offsets) != "[0 1]" {
		t.Fatal(offsets)
	}
	sr, e := s.GetSourceRecord(ctx, "nvd", "cve", "CVE-2025-0001")
	require(t, e)
	if !strings.Contains(string(sr.Raw), "retained") {
		t.Fatal(sr)
	}
}
func TestSyncLeaseAndStaleData(t *testing.T) {
	s, ctx := testStore(t)
	l, e := s.AcquireSync(ctx, "nvd", "cve", time.Minute)
	require(t, e)
	if _, e = s.AcquireSync(ctx, "nvd", "cve", time.Minute); !errors.Is(e, store.ErrConflict) {
		t.Fatal(e)
	}
	require(t, s.CheckpointSync(ctx, l, json.RawMessage(`{"start":2}`), time.Minute))
	fake := l
	fake.Token = store.NewID()
	if e = s.CheckpointSync(ctx, fake, json.RawMessage(`{}`), time.Minute); !errors.Is(e, store.ErrLeaseLost) {
		t.Fatal(e)
	}
	now := time.Now()
	r := store.SourceRecord{Source: "nvd", Stream: "cve", ID: "CVE-test", ModifiedAt: now, FetchedAt: now, Raw: json.RawMessage(`{"value":"new"}`)}
	require(t, s.UpsertSourceRecord(ctx, r))
	r.ModifiedAt = now.Add(-time.Hour)
	r.Raw = json.RawMessage(`{"value":"old"}`)
	require(t, s.UpsertSourceRecord(ctx, r))
	got, e := s.GetSourceRecord(ctx, "nvd", "cve", r.ID)
	require(t, e)
	if !strings.Contains(string(got.Raw), "new") {
		t.Fatal(got)
	}
	require(t, s.FinishSync(ctx, l, &now, true))
	if e = s.FinishSync(context.Background(), l, &now, true); !errors.Is(e, store.ErrLeaseLost) {
		t.Fatal(e)
	}
}

func TestNVDHistoryWindowsAndSourceAssigners(t *testing.T) {
	s, ctx := testStore(t)
	historySeen := false
	sourceSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "cvehistory"):
			historySeen = true
			if r.URL.Query().Get("changeStartDate") == "" || r.URL.Query().Get("changeEndDate") == "" {
				t.Error("history date window missing")
			}
			fmt.Fprint(w, `{"startIndex":0,"resultsPerPage":1,"totalResults":1,"cveChanges":[{"change":{"cveId":"CVE-2025-1","eventName":"Modified","cveChangeId":"00000000-0000-4000-8000-000000000011","created":"2025-01-01T00:00:00.000","details":[]}}]}`)
		case strings.Contains(r.URL.Path, "/source/"):
			sourceSeen = true
			fmt.Fprint(w, `{"startIndex":0,"resultsPerPage":1,"totalResults":1,"sources":[{"name":"Example","created":"2025-01-01T00:00:00.000","lastModified":"2025-01-01T00:00:00.000","sourceIdentifiers":["a@example.test","b@example.test"]}]}`)
		default:
			t.Errorf("unexpected URL: %s", r.URL)
		}
	}))
	defer server.Close()
	cfg := syncdata.NVDConfig{BaseURL: server.URL, MaxPages: 1, Interval: time.Nanosecond}
	if e := syncdata.NVD(ctx, s, cfg, "history"); !errors.Is(e, lookup.ErrPageLimit) {
		t.Fatal(e)
	}
	require(t, syncdata.NVD(ctx, s, cfg, "source"))
	if !historySeen || !sourceSeen {
		t.Fatal("API stream not called")
	}
	if _, e := s.GetSourceRecord(ctx, "nvd", "history", "00000000-0000-4000-8000-000000000011"); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"a@example.test", "b@example.test"} {
		if _, e := s.GetSourceRecord(ctx, "nvd", "source", id); e != nil {
			t.Fatal(e)
		}
	}
}

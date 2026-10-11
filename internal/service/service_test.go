package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mskmemory/gocpe-ai/internal/service"
	"github.com/mskmemory/gocpe-ai/internal/testutil"
)

const search = `{"name":"log4j-core","vendor":"Apache","options":{"provider":"openai","model":"test-model"}}`

func newService(t *testing.T, m service.Store, now func() time.Time) *service.Service {
	t.Helper()
	s, e := service.New(service.Config{Store: m, Providers: map[service.Provider][]string{"openai": {"test-model"}}, CursorKey: []byte(strings.Repeat("k", 32)), Now: now})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func expectCode(t *testing.T, e error, code string) {
	t.Helper()
	if e == nil || service.AsFault(e).Code != code {
		t.Fatalf("error=%v want %s", e, code)
	}
}
func TestIdempotencyAndIsolation(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewStore()
	s := newService(t, m, nil)
	j, e := s.Create(ctx, "alice", "package_search", "key", []byte(search))
	if e != nil {
		t.Fatal(e)
	}
	reordered := `{"options":{"model":"test-model","provider":"openai"},"vendor":"Apache","name":"log4j-core"}`
	m.SetReady(false)
	again, e := s.Create(ctx, "alice", "package_search", "key", []byte(reordered))
	if e != nil || again.ID != j.ID {
		t.Fatalf("replay %v %v", again, e)
	}
	_, e = s.Create(ctx, "alice", "package_search", "key", []byte(strings.ReplaceAll(search, "Apache", "Other")))
	expectCode(t, e, "IDEMPOTENCY_CONFLICT")
	_, e = s.Get(ctx, "bob", j.ID)
	expectCode(t, e, "NOT_FOUND")
	_, _, e = s.Cancel(ctx, "bob", j.ID)
	expectCode(t, e, "NOT_FOUND")
	_, e = s.Results(ctx, "bob", j.ID, "", 1)
	expectCode(t, e, "NOT_FOUND")
	_, e = s.Create(ctx, "alice", "package_search", "", []byte(search))
	expectCode(t, e, "SERVICE_UNAVAILABLE")
	a := m.Admission(j.ID)
	if a.Components[0].Package.ID != "component-1" || a.Components[0].SourcePointer != "" || len(a.Job.Options.Targets) != 2 || a.Job.Options.MaxCandidates != 5 {
		t.Fatalf("bad normalization: %+v", a)
	}
}
func TestConcurrentAdmission(t *testing.T) {
	m := testutil.NewStore()
	s := newService(t, m, nil)
	var wg sync.WaitGroup
	ids := make(chan string, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, e := s.Create(context.Background(), "alice", "package_search", "same-key", []byte(search))
			if e != nil {
				t.Error(e)
				return
			}
			ids <- j.ID
		}()
	}
	wg.Wait()
	close(ids)
	id := ""
	for got := range ids {
		if id == "" {
			id = got
		}
		if got != id {
			t.Error("duplicate job admitted")
		}
	}
}
func TestResultsAndCursor(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	m := testutil.NewStore()
	s := newService(t, m, func() time.Time { return now })
	ctx := context.Background()
	raw := `{"input":{"kind":"packages","packages":[{"id":"a","name":"A"},{"id":"b","name":"B"},{"id":"c","name":"C"}]},"options":{"provider":"openai","model":"test-model"}}`
	j, e := s.Create(ctx, "alice", "resolution", "", []byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Results(ctx, "alice", j.ID, "", 1)
	expectCode(t, e, "RESULTS_NOT_READY")
	m.Finish(j.ID, "partial")
	first, e := s.Results(ctx, "alice", j.ID, "", 1)
	if e != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first %+v %v", first, e)
	}
	second, e := s.Results(ctx, "alice", j.ID, first.NextCursor, 2)
	if e != nil || len(second.Items) != 2 || second.Items[0].Ordinal != 1 || second.NextCursor != "" {
		t.Fatalf("second %+v %v", second, e)
	}
	_, e = s.Results(ctx, "alice", j.ID, first.NextCursor+"x", 1)
	expectCode(t, e, "INVALID_CURSOR")
	_, e = s.CPEs(ctx, "alice", first.NextCursor, service.CPEQuery{})
	expectCode(t, e, "INVALID_CURSOR")
	now = now.Add(2 * time.Hour)
	_, e = s.Results(ctx, "alice", j.ID, first.NextCursor, 1)
	expectCode(t, e, "INVALID_CURSOR")
	now = now.Add(31 * 24 * time.Hour)
	_, e = s.Get(ctx, "alice", j.ID)
	expectCode(t, e, "NOT_FOUND")
}
func TestCancellation(t *testing.T) {
	for _, status := range []string{"queued", "running", "completed", "partial", "failed", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			m := testutil.NewStore()
			s := newService(t, m, nil)
			j, e := s.Create(context.Background(), "a", "package_search", "", []byte(search))
			if e != nil {
				t.Fatal(e)
			}
			m.SetStatus(j.ID, status)
			got, accepted, e := s.Cancel(context.Background(), "a", j.ID)
			if e != nil {
				t.Fatal(e)
			}
			if accepted == service.Terminal(status) {
				t.Fatal("wrong acceptance")
			}
			if status == "queued" && got.Status != "cancelled" {
				t.Fatal(got.Status)
			}
			if status == "running" && got.Status != "cancelling" {
				t.Fatal(got.Status)
			}
			if service.Terminal(status) && got.Status != status {
				t.Fatal("terminal state changed")
			}
		})
	}
}
func TestInputRejections(t *testing.T) {
	s := newService(t, testutil.NewStore(), nil)
	cases := []struct{ name, body, code string }{
		{"duplicate", strings.Replace(search, `"name":"log4j-core"`, `"name":"A","name":"B"`, 1), "INVALID_JSON"},
		{"trailing", search + ` {}`, "INVALID_JSON"},
		{"blank", strings.Replace(search, "Apache", "   ", 1), "INVALID_INPUT"},
		{"unknown", strings.Replace(search, `"name":`, `"unexpected":true,"name":`, 1), "INVALID_INPUT"},
		{"null", strings.Replace(search, `"Apache"`, `null`, 1), "INVALID_INPUT"},
		{"targets_empty", strings.Replace(search, `"model":"test-model"`, `"model":"test-model","targets":[]`, 1), "INVALID_INPUT"},
		{"model", strings.Replace(search, "test-model", "other", 1), "MODEL_NOT_ALLOWED"},
		{"invalid_cpe", strings.Replace(search, `"name":`, `"existing_cpes":["cpe:2.3:broken"],"name":`, 1), "INVALID_INPUT"},
		{"invalid_purl", strings.Replace(search, `"name":`, `"existing_purls":["https://example.com"],"name":`, 1), "INVALID_INPUT"},
		{"over_depth", strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66), "INVALID_INPUT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, e := s.Create(context.Background(), "a", "package_search", "", []byte(tc.body))
			expectCode(t, e, tc.code)
		})
	}
	_, e := s.Create(context.Background(), "a", "package_search", "", []byte(strings.Repeat(" ", service.MaxBodyBytes+1)))
	expectCode(t, e, "PAYLOAD_TOO_LARGE")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.Create(ctx, "a", "package_search", "", []byte(search))
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestDictionaryFilteringAndCursorScope(t *testing.T) {
	m := testutil.NewStore()
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		m.CPERecords = append(m.CPERecords, service.CPE{CPENameID: id, Vendor: "apache", Product: "log4j"})
		m.PURLRecords = append(m.PURLRecords, service.PURL{ID: id, Type: "maven", Name: "log4j", CanonicalPURL: "pkg:maven/log4j", OSVRecordIDs: []string{"TEST-1"}})
	}
	m.PURLRecords = append(m.PURLRecords, service.PURL{ID: service.NewID(), Type: "maven", Name: "unconfirmed"})
	s := newService(t, m, nil)
	a, e := s.CPEs(context.Background(), "a", "", service.CPEQuery{PageQuery: service.PageQuery{Limit: 1}, Vendor: "apache"})
	if e != nil || len(a.Items) != 1 || a.NextCursor == "" {
		t.Fatal(a, e)
	}
	_, e = s.CPEs(context.Background(), "a", a.NextCursor, service.CPEQuery{Vendor: "other"})
	expectCode(t, e, "INVALID_CURSOR")
	_, e = s.CPEs(context.Background(), "b", a.NextCursor, service.CPEQuery{Vendor: "apache"})
	expectCode(t, e, "INVALID_CURSOR")
	b, e := s.PURLs(context.Background(), "a", "", service.PURLQuery{Type: "maven"})
	if e != nil || len(b.Items) != 3 {
		t.Fatal(b, e)
	}
}
func TestExactNumbersInCanonicalHash(t *testing.T) {
	a, e := service.ParseJSON([]byte(`{"x":9007199254740992}`))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := service.ParseJSON([]byte(`{"x":9007199254740993}`))
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) == string(bj) {
		t.Fatal("lost integer precision")
	}
}

func TestCrossEndpointIdempotencyConflict(t *testing.T) {
	m := testutil.NewStore()
	s := newService(t, m, nil)
	_, e := s.Create(context.Background(), "a", "package_search", "same", []byte(search))
	if e != nil {
		t.Fatal(e)
	}
	raw := `{"input":{"kind":"packages","packages":[{"id":"component-1","name":"log4j-core","vendor":"Apache"}]},"options":{"provider":"openai","model":"test-model"}}`
	_, e = s.Create(context.Background(), "a", "resolution", "same", []byte(raw))
	expectCode(t, e, "IDEMPOTENCY_CONFLICT")
}

func TestIdentifierValidationAndDuplicateIDs(t *testing.T) {
	s := newService(t, testutil.NewStore(), nil)
	raw := `{"name":"component","vendor":"Vendor","existing_cpes":["cpe:2.3:a:vendor:product\\:name:1.0:*:*:*:*:*:*:*"],"existing_purls":["pkg:npm/%40scope/name@1.0?arch=x86_64"],"repository_urls":["https://example.com/repo"],"options":{"provider":"openai","model":"test-model"}}`
	if _, e := s.Create(context.Background(), "a", "package_search", "", []byte(raw)); e != nil {
		t.Fatal(e)
	}
	for _, u := range []string{"relative/path", "https://example.com/a b"} {
		bad := strings.Replace(raw, "https://example.com/repo", u, 1)
		_, e := s.Create(context.Background(), "a", "package_search", "", []byte(bad))
		expectCode(t, e, "INVALID_INPUT")
	}
	raw = `{"input":{"kind":"packages","packages":[{"id":"same","name":"A"},{"id":"same","name":"B"}]},"options":{"provider":"openai","model":"test-model"}}`
	_, e := s.Create(context.Background(), "a", "resolution", "", []byte(raw))
	expectCode(t, e, "INVALID_INPUT")
}

func TestPackageRawValuesPreserveExplicitEmptyFields(t *testing.T) {
	m := testutil.NewStore()
	s := newService(t, m, nil)
	raw := `{"input":{"kind":"packages","packages":[{"id":"a","name":"A","vendor":"","existing_purls":[]}]},"options":{"provider":"openai","model":"test-model"}}`
	j, e := s.Create(context.Background(), "a", "resolution", "", []byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	var original map[string]any
	_ = json.Unmarshal(m.Admission(j.ID).Components[0].RawValues, &original)
	if _, ok := original["vendor"]; !ok {
		t.Fatal("lost explicit vendor")
	}
	if _, ok := original["existing_purls"]; !ok {
		t.Fatal("lost empty purl array")
	}
}

func TestIntegralJSONNumberOptions(t *testing.T) {
	m := testutil.NewStore()
	s := newService(t, m, nil)
	raw := strings.Replace(search, `"model":"test-model"`, `"model":"test-model","max_candidates":1.0`, 1)
	j, e := s.Create(context.Background(), "a", "package_search", "", []byte(raw))
	if e != nil || j.Options.MaxCandidates != 1 {
		t.Fatalf("max candidates=%d error=%v", j.Options.MaxCandidates, e)
	}
}

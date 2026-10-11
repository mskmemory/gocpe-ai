package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mskmemory/gocpe-ai/internal/httpapi"
	"github.com/mskmemory/gocpe-ai/internal/service"
	"github.com/mskmemory/gocpe-ai/internal/testutil"
)

const aliceToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const bobToken = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const readerToken = "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr"
const searchBody = `{"name":"log4j-core","vendor":"Apache","options":{"provider":"openai","model":"test-model"}}`

type fixture struct {
	handler http.Handler
	svc     *service.Service
	store   *testutil.MemoryStore
}

func setup(t *testing.T, store service.Store, providers map[service.Provider][]string) fixture {
	t.Helper()
	s, e := service.New(service.Config{Store: store, Providers: providers, CursorKey: []byte(strings.Repeat("k", 32))})
	if e != nil {
		t.Fatal(e)
	}
	auth, e := httpapi.NewStaticAuth(map[string]httpapi.Principal{aliceToken: {OwnerID: "alice", Read: true, Write: true}, bobToken: {OwnerID: "bob", Read: true, Write: true}, readerToken: {OwnerID: "reader", Read: true}})
	if e != nil {
		t.Fatal(e)
	}
	h, e := httpapi.New(s, auth)
	if e != nil {
		t.Fatal(e)
	}
	m, _ := store.(*testutil.MemoryStore)
	return fixture{h, s, m}
}
func newFixture(t *testing.T) fixture {
	return setup(t, testutil.NewStore(), map[service.Provider][]string{"openai": {"test-model"}})
}
func (f fixture) request(t *testing.T, method, path, body, token string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("non-JSON response %d %s", w.Code, w.Body.String())
	}
	if !service.ValidID(w.Header().Get("X-Request-ID")) {
		t.Fatal("missing request ID")
	}
	if w.Code >= 400 {
		var e service.ErrorResponse
		if json.Unmarshal(w.Body.Bytes(), &e) != nil {
			t.Fatal(w.Body.String())
		}
		if e.Error.RequestID != w.Header().Get("X-Request-ID") {
			t.Fatal("request ID mismatch")
		}
		if err := f.svc.ValidateOutput("ErrorResponse", e); err != nil {
			t.Fatal(err)
		}
	}
	return w
}
func assertStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d want %d body=%s", w.Code, status, w.Body.String())
	}
}
func TestHTTPJobLifecycle(t *testing.T) {
	f := newFixture(t)
	w := f.request(t, "POST", "/v1/package-searches", searchBody, aliceToken, map[string]string{"Idempotency-Key": "search-1"})
	assertStatus(t, w, 202)
	var j service.Job
	if e := json.Unmarshal(w.Body.Bytes(), &j); e != nil {
		t.Fatal(e)
	}
	if j.Status != "queued" || j.Progress.Total != 1 || w.Header().Get("Location") != "/v1/resolutions/"+j.ID || w.Header().Get("Retry-After") != "2" {
		t.Fatal(j, w.Header())
	}
	w = f.request(t, "POST", "/v1/package-searches", searchBody, aliceToken, map[string]string{"Idempotency-Key": "search-1"})
	assertStatus(t, w, 202)
	var replay service.Job
	_ = json.Unmarshal(w.Body.Bytes(), &replay)
	if replay.ID != j.ID {
		t.Fatal("replay changed job")
	}
	path := "/v1/resolutions/" + j.ID
	assertStatus(t, f.request(t, "GET", path, "", bobToken, nil), 404)
	assertStatus(t, f.request(t, "POST", path+"/cancel", "", bobToken, nil), 404)
	assertStatus(t, f.request(t, "GET", path+"/results", "", bobToken, nil), 404)
	assertStatus(t, f.request(t, "GET", path+"/results", "", aliceToken, nil), 409)
	assertStatus(t, f.request(t, "GET", path, "", aliceToken, nil), 200)
	assertStatus(t, f.request(t, "POST", path+"/cancel", "", aliceToken, nil), 202)
	assertStatus(t, f.request(t, "POST", path+"/cancel", "", aliceToken, nil), 200)
	w = f.request(t, "GET", path+"/results", "", aliceToken, nil)
	assertStatus(t, w, 200)
	var page service.ResultPage
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if page.Items == nil || len(page.Items) != 0 {
		t.Fatal(page)
	}
}
func TestHTTPPackageBatchAndResults(t *testing.T) {
	f := newFixture(t)
	raw := `{"input":{"kind":"packages","packages":[{"id":"a","name":"A"},{"id":"b","name":"B"}]},"options":{"provider":"openai","model":"test-model","targets":["purl"]}}`
	w := f.request(t, "POST", "/v1/resolutions", raw, aliceToken, nil)
	assertStatus(t, w, 202)
	var j service.Job
	_ = json.Unmarshal(w.Body.Bytes(), &j)
	f.store.Finish(j.ID, "completed")
	path := "/v1/resolutions/" + j.ID + "/results?limit=1"
	w = f.request(t, "GET", path, "", aliceToken, nil)
	assertStatus(t, w, 200)
	var page service.ResultPage
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatal(page)
	}
	w = f.request(t, "GET", path+"&cursor="+page.NextCursor, "", aliceToken, nil)
	assertStatus(t, w, 200)
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if page.Items[0].ComponentID != "b" {
		t.Fatal(page)
	}
}
func TestHTTPValidationAndAuth(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name, method, path, body, token string
		headers                         map[string]string
		status                          int
	}{
		{"missing_auth", "GET", "/v1/providers", "", "", nil, 401},
		{"bad_auth", "GET", "/v1/providers", "", "invalid", nil, 401},
		{"scope", "POST", "/v1/package-searches", searchBody, readerToken, nil, 403},
		{"unknown_route", "GET", "/v1/nope", "", aliceToken, nil, 404},
		{"method", "DELETE", "/v1/providers", "", aliceToken, nil, 405},
		{"trailing_route", "GET", "/v1/providers/", "", aliceToken, nil, 404},
		{"bad_id", "GET", "/v1/resolutions/invalid", "", aliceToken, nil, 404},
		{"content_type", "POST", "/v1/package-searches", searchBody, aliceToken, map[string]string{"Content-Type": "text/plain"}, 415},
		{"charset", "POST", "/v1/package-searches", searchBody, aliceToken, map[string]string{"Content-Type": "application/json;charset=shift_jis"}, 415},
		{"compression", "POST", "/v1/package-searches", searchBody, aliceToken, map[string]string{"Content-Encoding": "gzip"}, 415},
		{"broken_json", "POST", "/v1/package-searches", "{", aliceToken, nil, 400},
		{"unknown_field", "POST", "/v1/package-searches", strings.Replace(searchBody, `"name":`, `"secret":true,"name":`, 1), aliceToken, nil, 422},
		{"blank_vendor", "POST", "/v1/package-searches", strings.Replace(searchBody, "Apache", " ", 1), aliceToken, nil, 422},
		{"unknown_query", "GET", "/v1/providers?foo=1", "", aliceToken, nil, 400},
		{"repeated_limit", "GET", "/v1/cpes?limit=1&limit=2", "", aliceToken, nil, 400},
		{"bad_limit", "GET", "/v1/cpes?limit=0", "", aliceToken, nil, 400},
		{"large_limit", "GET", "/v1/cpes?limit=201", "", aliceToken, nil, 400},
		{"bad_boolean", "GET", "/v1/cpes?deprecated=1", "", aliceToken, nil, 400},
		{"oversize", "POST", "/v1/package-searches", strings.Repeat(" ", service.MaxBodyBytes+1), aliceToken, nil, 413},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := f.request(t, tc.method, tc.path, tc.body, tc.token, tc.headers)
			assertStatus(t, w, tc.status)
		})
	}
	w := f.request(t, "GET", "/v1/providers", "", aliceToken, nil)
	assertStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "test-model") {
		t.Fatal(w.Body.String())
	}
}
func TestHTTPDictionaryPages(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC()
	f.store.CPERecords = []service.CPE{{CPENameID: "00000000-0000-4000-8000-000000000001", CPEName: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", Vendor: "apache", Product: "log4j", Version: "*", Titles: []string{"Apache Log4j"}, ReplacedBy: []string{}, SourceModifiedAt: now, FetchedAt: now}}
	f.store.PURLRecords = []service.PURL{{ID: "00000000-0000-4000-8000-000000000001", CanonicalPURL: "pkg:maven/org.apache/log4j", Type: "maven", Namespace: "org.apache", Name: "log4j", Qualifiers: map[string]string{}, OSVRecordIDs: []string{"TEST-1"}, ObservedAt: now}}
	assertStatus(t, f.request(t, "GET", "/v1/cpes?vendor=apache&q=log4j", "", aliceToken, nil), 200)
	w := f.request(t, "GET", "/v1/cpes?vendor=other", "", aliceToken, nil)
	assertStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal(w.Body.String())
	}
	assertStatus(t, f.request(t, "GET", "/v1/purls?type=maven&name=log4j", "", aliceToken, nil), 200)
}

type brokenStore struct{ service.UnavailableStore }

func (brokenStore) Admit(context.Context, service.Admission) (service.StoredJob, error) {
	return service.StoredJob{}, errors.New("PRIVATE_API_KEY_AND_SBOM")
}
func TestUnconfiguredAndSanitizedFailure(t *testing.T) {
	f := setup(t, service.UnavailableStore{}, nil)
	w := f.request(t, "GET", "/v1/providers", "", aliceToken, nil)
	assertStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatal(w.Body.String())
	}
	for _, path := range []string{"/v1/cpes", "/v1/purls"} {
		w = f.request(t, "GET", path, "", aliceToken, nil)
		assertStatus(t, w, 503)
	}
	w = f.request(t, "POST", "/v1/package-searches", searchBody, aliceToken, nil)
	assertStatus(t, w, 503)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("missing retry hint")
	}
	f = setup(t, brokenStore{}, map[service.Provider][]string{"openai": {"test-model"}})
	w = f.request(t, "POST", "/v1/package-searches", searchBody, aliceToken, nil)
	assertStatus(t, w, 500)
	if bytes.Contains(w.Body.Bytes(), []byte("PRIVATE")) {
		t.Fatal("backend secret leaked")
	}
}

func TestRepeatedHeadersAndEmptyKey(t *testing.T) {
	f := newFixture(t)
	for _, header := range []string{"Authorization", "Idempotency-Key"} {
		t.Run(header, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/package-searches", strings.NewReader(searchBody))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+aliceToken)
			if header == "Authorization" {
				r.Header.Add(header, "Bearer "+bobToken)
			} else {
				r.Header.Add(header, "one")
				r.Header.Add(header, "two")
			}
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, r)
			expected := 422
			if header == "Authorization" {
				expected = 401
			}
			assertStatus(t, w, expected)
		})
	}
	assertStatus(t, f.request(t, "POST", "/v1/package-searches", searchBody, aliceToken, map[string]string{"Idempotency-Key": ""}), 422)
}

type limitedStore struct{ service.UnavailableStore }

func (limitedStore) Admit(context.Context, service.Admission) (service.StoredJob, error) {
	return service.StoredJob{}, service.ErrRateLimited
}
func TestAdmissionRateLimit(t *testing.T) {
	f := setup(t, limitedStore{}, map[service.Provider][]string{"openai": {"test-model"}})
	w := f.request(t, "POST", "/v1/package-searches", searchBody, aliceToken, nil)
	assertStatus(t, w, 429)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("missing retry hint")
	}
}

package nvd

import (
	"context"
	"errors"
	"fmt"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testCPE = `cpe:2.3:a:example:demo:1.0:*:*:*:*:*:*:*`
const product = `{"cpe":{"cpeName":"` + testCPE + `","cpeNameId":"00000000-0000-4000-8000-000000000001","lastModified":"2025-01-01T00:00:00.000","deprecated":true,"deprecatedBy":[{"cpeNameId":"00000000-0000-4000-8000-000000000002"}],"extra":{"preserved":true}}}`

func TestPaging(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "test-key" {
			t.Error("missing optional key")
		}
		if r.URL.Query().Get("keywordSearch") != "demo" {
			t.Error("query lost")
		}
		fmt.Fprintf(w, `{"startIndex":%s,"resultsPerPage":1,"totalResults":2,"products":[%s]}`, r.URL.Query().Get("startIndex"), product)
	}))
	defer s.Close()
	c := New(Config{Endpoint: s.URL, PageSize: 1, APIKey: "test-key"})
	r, e := c.Search(context.Background(), Query{Keyword: "demo"})
	if e != nil || !r.Complete || len(r.Records) != 2 || len(r.Evidence) != 2 || !r.Records[0].Deprecated || len(r.Records[0].ReplacedBy) != 1 {
		t.Fatalf("%+v %v", r, e)
	}
	c = New(Config{Endpoint: s.URL, PageSize: 1, MaxPages: 1, APIKey: "test-key"})
	r, e = c.Search(context.Background(), Query{Keyword: "demo"})
	if !errors.Is(e, lookup.ErrPageLimit) || r.Complete {
		t.Fatalf("%+v %v", r, e)
	}
	if Registered(`cpe:2.3:a:example:demo:*:*:*:*:*:*:*:*`, testCPE) || !Registered(testCPE, testCPE) {
		t.Fatal("wildcard confused with registered name")
	}
}
func TestBadResponses(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `bad`, `{"startIndex":1,"resultsPerPage":0,"totalResults":1,"products":[]}`, `{"startIndex":0,"resultsPerPage":0,"totalResults":1,"products":[]}`, `{"startIndex":0,"resultsPerPage":1,"totalResults":1,"products":[{"cpe":{}}]}`} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, raw) }))
		r, e := New(Config{Endpoint: s.URL}).Search(context.Background(), Query{})
		s.Close()
		if e == nil || r.Complete {
			t.Fatalf("accepted %s", raw)
		}
	}
}

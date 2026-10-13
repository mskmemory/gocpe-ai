package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"github.com/mskmemory/gocpe-ai/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const record = `{"id":"OSV-TEST","modified":"2025-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"wrong","purl":"pkg:npm/wrong"}},{"package":{"ecosystem":"npm","name":"demo","purl":"pkg:npm/demo"},"versions":["1.0"]}],"extra":{"preserved":true}}`

func TestQueryPagingAndMatch(t *testing.T) {
	n := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		var q Query
		json.NewDecoder(r.Body).Decode(&q)
		if r.Method != "POST" || q.Package.PURL != "pkg:npm/demo" || q.Version != "" {
			t.Error("bad request")
		}
		if n == 1 {
			fmt.Fprint(w, `{"next_page_token":"next"}`)
		} else {
			if q.PageToken != "next" {
				t.Error("missing token")
			}
			fmt.Fprintf(w, `{"vulns":[%s]}`, record)
		}
	}))
	defer s.Close()
	q, e := PackageQuery("pkg:npm/demo@1.0?arch=x86#src")
	if e != nil {
		t.Fatal(e)
	}
	r, e := New(Config{Endpoint: s.URL}).Query(context.Background(), q)
	if e != nil || !r.Complete || len(r.Records) != 1 || len(r.Evidence) != 2 {
		t.Fatalf("%+v %v", r, e)
	}
	a := r.Records[0].Affected
	if Match(q, a[0]) != "" || Match(q, a[1]) != "purl_match" {
		t.Fatal("wrong affected matched")
	}
	a[1].Name = "other"
	if Match(q, a[1]) != "" {
		t.Fatal("conflicting metadata matched")
	}
}
func TestEmptyUnsupportedAndDuplicateVersion(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{}`) }))
	defer s.Close()
	c := New(Config{Endpoint: s.URL})
	r, e := c.Query(context.Background(), Query{Package: Package{PURL: "pkg:npm/demo"}})
	if e != nil || !r.Complete || len(r.Records) != 0 {
		t.Fatal(r, e)
	}
	for _, q := range []Query{{Package: Package{PURL: "pkg:npm/demo@1.0"}, Version: "1.0"}, {Package: Package{PURL: "pkg:npm/demo", Name: "demo"}}, {Package: Package{Name: "demo"}}} {
		if !errors.Is(Validate(q), store.ErrInvalid) {
			t.Fatal(q)
		}
	}
	if !errors.Is(Validate(Query{Package: Package{PURL: "pkg:generic/demo"}}), lookup.ErrUnsupported) {
		t.Fatal("unsupported")
	}
}
func TestLoopAndLimit(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"next_page_token":"loop"}`) }))
	defer s.Close()
	q := Query{Package: Package{Name: "demo", Ecosystem: "npm"}}
	for _, max := range []int{1, 5} {
		r, e := New(Config{Endpoint: s.URL, MaxPages: max}).Query(context.Background(), q)
		if e == nil || r.Complete {
			t.Fatal(r, e)
		}
	}
}
func TestDecodeWithdrawnAndDerived(t *testing.T) {
	r, e := DecodeRecord([]byte(`{"id":"W","modified":"2025-01-01T00:00:00Z","withdrawn":"2025-01-02T00:00:00Z"}`), time.Now())
	if e != nil || r.WithdrawnAt == nil {
		t.Fatal(r, e)
	}
	for _, p := range []Package{{Name: "@scope/name", Ecosystem: "npm"}, {Name: "a.b:c", Ecosystem: "Maven"}, {Name: "github.com/A/B", Ecosystem: "Go"}, {Name: "Foo__Bar", Ecosystem: "PyPI"}} {
		v, ok := FromPackage(p)
		if !ok {
			t.Fatal(p)
		}
		q := Query{Package: Package{PURL: v.ToString()}}
		if Match(q, store.OSVAffected{Name: p.Name, Ecosystem: p.Ecosystem}) != "ecosystem_name_match" {
			t.Fatal(p)
		}
	}
}

package postgres

import (
	"errors"
	"github.com/mskmemory/gocpe-ai/internal/store"
	"testing"
)

func TestIdentifierNormalization(t *testing.T) {
	c, e := parseCPE(`cpe:2.3:a:vendor:foo\:bar:1.0:*:-:*:*:*:*:*`)
	if e != nil {
		t.Fatal(e)
	}
	if c.product != `foo\:bar` || c.attributes["update"] != "*" || c.attributes["edition"] != "-" {
		t.Fatalf("%+v", c)
	}
	if _, e = parseCPE("not-a-cpe"); !errors.Is(e, store.ErrInvalid) {
		t.Fatal(e)
	}
	p, e := canonicalPURL("pkg:pypi/Django_REST.Framework@1.0?z=x&a=y#src/file")
	if e != nil {
		t.Fatal(e)
	}
	if p.canonical != "pkg:pypi/django-rest-framework@1.0?a=y&z=x#src/file" {
		t.Fatal(p.canonical)
	}
}
func TestIdempotencyFingerprint(t *testing.T) {
	a, e := requestHash(store.EndpointResolution, []byte(`{"b":[1,2],"a":"x"}`))
	if e != nil {
		t.Fatal(e)
	}
	b, e := requestHash(store.EndpointResolution, []byte(`{ "a":"x", "b":[1,2] }`))
	if e != nil {
		t.Fatal(e)
	}
	if a != b {
		t.Fatal("object ordering changed identity")
	}
	c, _ := requestHash(store.EndpointResolution, []byte(`{"a":"x","b":[2,1]}`))
	if a == c {
		t.Fatal("array order lost")
	}
	d, _ := requestHash(store.EndpointPackageSearch, []byte(`{"a":"x","b":[1,2]}`))
	if a == d {
		t.Fatal("endpoint not hashed")
	}
	if _, e = requestHash(store.EndpointResolution, []byte(`{} {}`)); e == nil {
		t.Fatal("trailing JSON accepted")
	}
}

// Package osv queries vulnerability records. Absence is never proof of safety.
package osv

import (
	"context"
	"encoding/json"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"github.com/mskmemory/gocpe-ai/internal/store"
	packageurl "github.com/package-url/packageurl-go"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const Endpoint = "https://api.osv.dev/v1/query"

type Config struct {
	HTTP     lookup.Config
	Endpoint string
	MaxPages int
}
type Client struct {
	http *lookup.HTTP
	cfg  Config
}

func New(c Config) *Client {
	if c.Endpoint == "" {
		c.Endpoint = Endpoint
	}
	if c.MaxPages <= 0 {
		c.MaxPages = 100
	}
	return &Client{lookup.NewHTTP(c.HTTP), c}
}

type Package struct {
	PURL      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}
type Query struct {
	Package   Package `json:"package"`
	Version   string  `json:"version,omitempty"`
	PageToken string  `json:"page_token,omitempty"`
}
type Result struct {
	lookup.Observation
	Records []store.OSVRecord
}

var ecosystems = map[string]string{"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go"}
var pep503 = regexp.MustCompile(`[-_.]+`)

func ParsePURL(raw string) (packageurl.PackageURL, error) {
	p, e := packageurl.FromString(raw)
	if e == nil && p.Type == "pypi" {
		p.Name = pep503.ReplaceAllString(strings.ToLower(p.Name), "-")
	}
	return p, e
}

// PackageQuery explicitly strips version, qualifiers and subpath for identity lookup.
// The caller retains the original complete PURL in its candidate and evidence query.
func PackageQuery(raw string) (Query, error) {
	p, e := ParsePURL(raw)
	if e != nil {
		return Query{}, store.ErrInvalid
	}
	if ecosystems[p.Type] == "" {
		return Query{}, lookup.ErrUnsupported
	}
	p.Version = ""
	p.Qualifiers = nil
	p.Subpath = ""
	return Query{Package: Package{PURL: p.ToString()}}, nil
}
func Validate(q Query) error {
	p := q.Package
	if p.PURL != "" {
		if p.Name != "" || p.Ecosystem != "" {
			return store.ErrInvalid
		}
		v, e := ParsePURL(p.PURL)
		if e != nil {
			return store.ErrInvalid
		}
		if v.Version != "" && q.Version != "" {
			return store.ErrInvalid
		}
		if ecosystems[v.Type] == "" {
			return lookup.ErrUnsupported
		}
		return nil
	}
	if p.Name == "" || p.Ecosystem == "" {
		return store.ErrInvalid
	}
	for _, v := range ecosystems {
		if v == p.Ecosystem {
			return nil
		}
	}
	return lookup.ErrUnsupported
}
func (c *Client) Query(ctx context.Context, q Query) (out Result, err error) {
	defer func() {
		if err != nil {
			out.Fail(err)
		}
	}()
	if err = Validate(q); err != nil {
		return out, err
	}
	seen := map[string]bool{}
	for page := 0; page < c.cfg.MaxPages; page++ {
		if seen[q.PageToken] {
			return out, lookup.ErrProtocol
		}
		seen[q.PageToken] = true
		body, _ := json.Marshal(q)
		raw, e := c.http.Do(ctx, http.MethodPost, c.cfg.Endpoint, body, nil)
		if e != nil {
			return out, e
		}
		out.Add("osv", c.cfg.Endpoint, "package", q, raw)
		var p struct {
			Vulns []json.RawMessage `json:"vulns"`
			Next  string            `json:"next_page_token"`
		}
		if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &p) != nil {
			return out, lookup.ErrProtocol
		}
		for _, v := range p.Vulns {
			r, e := DecodeRecord(v, out.Evidence[len(out.Evidence)-1].ObservedAt)
			if e != nil {
				return out, e
			}
			out.Records = append(out.Records, r)
		}
		if p.Next == "" {
			out.Complete = true
			return out, nil
		}
		q.PageToken = p.Next
	}
	return out, lookup.ErrPageLimit
}

// DecodeRecord retains all fields, including unsupported and withdrawn records.
func DecodeRecord(raw json.RawMessage, at time.Time) (store.OSVRecord, error) {
	var v struct {
		ID        string            `json:"id"`
		Modified  time.Time         `json:"modified"`
		Withdrawn *time.Time        `json:"withdrawn"`
		Affected  []json.RawMessage `json:"affected"`
	}
	if json.Unmarshal(raw, &v) != nil || v.ID == "" || v.Modified.IsZero() {
		return store.OSVRecord{}, lookup.ErrProtocol
	}
	r := store.OSVRecord{ID: v.ID, ModifiedAt: v.Modified, WithdrawnAt: v.Withdrawn, FetchedAt: at, Raw: raw}
	for i, rawAffected := range v.Affected {
		var a struct {
			Package Package `json:"package"`
		}
		if json.Unmarshal(rawAffected, &a) != nil {
			return r, lookup.ErrProtocol
		}
		item := store.OSVAffected{Index: i, Ecosystem: a.Package.Ecosystem, Name: a.Package.Name, RawPURL: a.Package.PURL, Mapping: store.PURLUnavailable, Affected: rawAffected}
		if item.Ecosystem == "" || item.Name == "" {
			return r, lookup.ErrProtocol
		}
		if item.RawPURL != "" {
			if p, e := ParsePURL(item.RawPURL); e == nil {
				item.PURL = p.ToString()
				item.Mapping = store.PURLExplicit
			}
		} else if p, ok := FromPackage(a.Package); ok {
			item.PURL = p.ToString()
			item.Mapping = store.PURLDerived
		}
		r.Affected = append(r.Affected, item)
	}
	return r, nil
}

// FromPackage uses ecosystem naming rules, not ad-hoc PURL string splitting.
func FromPackage(p Package) (packageurl.PackageURL, bool) {
	typ := ""
	for t, e := range ecosystems {
		if e == p.Ecosystem {
			typ = t
		}
	}
	if typ == "" || p.Name == "" {
		return packageurl.PackageURL{}, false
	}
	ns, name := "", p.Name
	switch typ {
	case "maven":
		var ok bool
		ns, name, ok = strings.Cut(name, ":")
		if !ok || ns == "" || name == "" {
			return packageurl.PackageURL{}, false
		}
	case "golang", "npm":
		if i := strings.LastIndex(name, "/"); i >= 0 {
			ns, name = name[:i], name[i+1:]
		}
	}
	v := packageurl.NewPackageURL(typ, ns, name, "", nil, "")
	parsed, e := ParsePURL(v.ToString())
	return parsed, e == nil
}

// Match examines one affected entry. A different entry cannot supply missing fields.
// Only type/namespace/name are confirmed, not version, qualifiers or subpath.
func Match(q Query, a store.OSVAffected) string {
	var expected packageurl.PackageURL
	if q.Package.PURL != "" {
		p, e := ParsePURL(q.Package.PURL)
		if e != nil {
			return ""
		}
		expected = p
	} else {
		p, ok := FromPackage(q.Package)
		if !ok {
			return ""
		}
		expected = p
	}
	same := func(p packageurl.PackageURL) bool {
		return p.Type == expected.Type && p.Namespace == expected.Namespace && p.Name == expected.Name
	}
	// Conflicting explicit package metadata must not be rescued by its PURL.
	metadata, ok := FromPackage(Package{Name: a.Name, Ecosystem: a.Ecosystem})
	if !ok || !same(metadata) {
		return ""
	}
	if a.RawPURL != "" {
		p, e := ParsePURL(a.RawPURL)
		if e != nil || !same(p) {
			return ""
		}
		return "purl_match"
	}
	return "ecosystem_name_match"
}

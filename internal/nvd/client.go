// Package nvd fetches registered CPE names, never synthetic match criteria.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"github.com/mskmemory/gocpe-ai/internal/store"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const Endpoint = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

type Config struct {
	HTTP               lookup.Config
	Endpoint, APIKey   string
	PageSize, MaxPages int
}
type Client struct {
	http *lookup.HTTP
	cfg  Config
}

func New(c Config) *Client {
	if c.Endpoint == "" {
		c.Endpoint = Endpoint
	}
	if c.PageSize <= 0 || c.PageSize > 10000 {
		c.PageSize = 10000
	}
	if c.MaxPages <= 0 {
		c.MaxPages = 100
	}
	return &Client{lookup.NewHTTP(c.HTTP), c}
}

type Query struct {
	Keyword     string `json:"keyword,omitempty"`
	MatchString string `json:"match_string,omitempty"`
	NameID      string `json:"name_id,omitempty"`
}
type Result struct {
	lookup.Observation
	Records []store.CPERecord
}

func (c *Client) Search(ctx context.Context, q Query) (out Result, err error) {
	defer func() {
		if err != nil {
			out.Fail(err)
		}
	}()
	if q.MatchString != "" {
		if _, e := naming.UnbindFS(q.MatchString); e != nil {
			return out, fmt.Errorf("%w: match string", store.ErrInvalid)
		}
	}
	if q.NameID != "" && !store.ValidUUID(q.NameID) {
		return out, store.ErrInvalid
	}
	start := 0
	total := -1
	for page := 0; page < c.cfg.MaxPages; page++ {
		values := url.Values{"startIndex": {strconv.Itoa(start)}, "resultsPerPage": {strconv.Itoa(c.cfg.PageSize)}}
		if q.Keyword != "" {
			values.Set("keywordSearch", q.Keyword)
		}
		if q.MatchString != "" {
			values.Set("cpeMatchString", q.MatchString)
		}
		if q.NameID != "" {
			values.Set("cpeNameId", q.NameID)
		}
		headers := http.Header{}
		if c.cfg.APIKey != "" {
			headers.Set("apiKey", c.cfg.APIKey)
		}
		raw, e := c.http.Do(ctx, http.MethodGet, c.cfg.Endpoint+"?"+values.Encode(), nil, headers)
		if e != nil {
			return out, e
		}
		out.Add("nvd", c.cfg.Endpoint, "product", values, raw)
		var p struct {
			ResultsPerPage *int              `json:"resultsPerPage"`
			StartIndex     *int              `json:"startIndex"`
			TotalResults   *int              `json:"totalResults"`
			Products       []json.RawMessage `json:"products"`
		}
		if json.Unmarshal(raw, &p) != nil || p.ResultsPerPage == nil || p.StartIndex == nil || p.TotalResults == nil || *p.StartIndex != start || *p.TotalResults < 0 || *p.ResultsPerPage != len(p.Products) {
			return out, lookup.ErrProtocol
		}
		if total >= 0 && total != *p.TotalResults {
			return out, fmt.Errorf("%w: total changed during paging", lookup.ErrProtocol)
		}
		total = *p.TotalResults
		for _, product := range p.Products {
			rec, e := DecodeProduct(product, out.Evidence[len(out.Evidence)-1].ObservedAt)
			if e != nil {
				return out, e
			}
			out.Records = append(out.Records, rec)
		}
		start += len(p.Products)
		if start >= total {
			out.Complete = true
			return out, nil
		}
		if len(p.Products) == 0 {
			return out, lookup.ErrProtocol
		}
	}
	return out, lookup.ErrPageLimit
}
func DecodeProduct(raw json.RawMessage, at time.Time) (store.CPERecord, error) {
	var p struct {
		CPE struct {
			Name       string `json:"cpeName"`
			ID         string `json:"cpeNameId"`
			Deprecated bool   `json:"deprecated"`
			Modified   string `json:"lastModified"`
			Titles     []struct {
				Title string `json:"title"`
			} `json:"titles"`
			Replacements []struct {
				ID string `json:"cpeNameId"`
			} `json:"deprecatedBy"`
		} `json:"cpe"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return store.CPERecord{}, lookup.ErrProtocol
	}
	v := p.CPE
	modified, e := ParseTime(v.Modified)
	if e != nil || !store.ValidUUID(v.ID) {
		return store.CPERecord{}, lookup.ErrProtocol
	}
	if _, e = naming.UnbindFS(v.Name); e != nil {
		return store.CPERecord{}, lookup.ErrProtocol
	}
	rec := store.CPERecord{NameID: v.ID, Name: v.Name, Deprecated: v.Deprecated, SourceModifiedAt: modified, FetchedAt: at, Raw: raw}
	for _, t := range v.Titles {
		rec.Titles = append(rec.Titles, t.Title)
	}
	for _, r := range v.Replacements {
		if !store.ValidUUID(r.ID) {
			return rec, lookup.ErrProtocol
		}
		rec.ReplacedBy = append(rec.ReplacedBy, r.ID)
	}
	return rec, nil
}
func ParseTime(s string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e == nil {
		return t, nil
	}
	return time.Parse("2006-01-02T15:04:05.999999999", s)
}

// Registered compares all parsed attributes; matching a wildcard search is not registration.
func Registered(input, registered string) bool {
	a, e := naming.UnbindFS(input)
	if e != nil {
		return false
	}
	b, e := naming.UnbindFS(registered)
	return e == nil && naming.BindToFS(a) == naming.BindToFS(b)
}

// Package syncdata implements resumable full-source ingestion, separate from
// package resolution. Network calls never hold database transactions open.
package syncdata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"github.com/mskmemory/gocpe-ai/internal/nvd"
	"github.com/mskmemory/gocpe-ai/internal/store"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Repository interface {
	store.Dictionary
	store.SyncStore
}
type NVDConfig struct {
	HTTP            lookup.Config
	BaseURL, APIKey string
	MaxPages        int
	Interval        time.Duration
	LeaseDuration   time.Duration
}
type pageCursor struct {
	Start       int       `json:"start"`
	Total       int       `json:"total"`
	Started     time.Time `json:"started"`
	Endpoint    string    `json:"endpoint"`
	WindowStart time.Time `json:"window_start,omitempty"`
	WindowEnd   time.Time `json:"window_end,omitempty"`
}
type streamSpec struct {
	path, array, object, id, modified string
	size                              int
}

var streams = map[string]streamSpec{
	"cpe":     {"cpes", "products", "cpe", "cpeNameId", "lastModified", 10000},
	"cve":     {"cves", "vulnerabilities", "cve", "id", "lastModified", 2000},
	"match":   {"cpematch", "matchStrings", "matchString", "matchCriteriaId", "lastModified", 500},
	"history": {"cvehistory", "cveChanges", "change", "cveChangeId", "created", 5000},
	"source":  {"source", "sources", "", "sourceIdentifier", "lastModified", 1000},
}

// NVD walks an entire API stream. MaxPages=0 means no page cap. Re-running a
// completed stream performs a full refresh; a failed stream resumes its page.
func NVD(ctx context.Context, repo Repository, c NVDConfig, stream string) (err error) {
	spec, ok := streams[stream]
	if !ok {
		return store.ErrInvalid
	}
	if c.BaseURL == "" {
		c.BaseURL = "https://services.nvd.nist.gov/rest/json"
	}
	endpoint := c.BaseURL + "/" + spec.path + "/2.0"
	if c.Interval <= 0 {
		c.Interval = 6 * time.Second
	}
	if c.LeaseDuration <= 0 {
		c.LeaseDuration = 15 * time.Minute
	}
	lease, e := repo.AcquireSync(ctx, "nvd", stream, c.LeaseDuration)
	if e != nil {
		return e
	}
	complete := false
	var watermark *time.Time
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		err = errors.Join(err, repo.FinishSync(cleanup, lease, watermark, complete))
	}()
	now := time.Now().UTC()
	cursor := pageCursor{Total: -1, Started: now, Endpoint: endpoint}
	if stream == "history" {
		cursor.WindowStart = time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
		cursor.WindowEnd = cursor.WindowStart.Add(119 * 24 * time.Hour)
	}
	if len(lease.Cursor) > 2 {
		if e = json.Unmarshal(lease.Cursor, &cursor); e != nil {
			return e
		}
		if cursor.Endpoint != endpoint {
			return errors.New("sync: endpoint differs from checkpoint")
		}
	}
	transport := lookup.NewHTTP(c.HTTP)
	for page := 0; c.MaxPages <= 0 || page < c.MaxPages; page++ {
		if e = lookup.Wait(ctx, c.Interval); e != nil {
			return e
		}
		q := url.Values{"startIndex": {strconv.Itoa(cursor.Start)}, "resultsPerPage": {strconv.Itoa(spec.size)}}
		if stream == "history" {
			end := cursor.WindowEnd
			if end.After(cursor.Started) {
				end = cursor.Started
			}
			q.Set("changeStartDate", cursor.WindowStart.Format("2006-01-02T15:04:05.000"))
			q.Set("changeEndDate", end.Format("2006-01-02T15:04:05.000"))
		}
		headers := http.Header{}
		if c.APIKey != "" {
			headers.Set("apiKey", c.APIKey)
		}
		raw, e := transport.Do(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil, headers)
		if e != nil {
			return e
		}
		var p map[string]json.RawMessage
		if json.Unmarshal(raw, &p) != nil {
			return lookup.ErrProtocol
		}
		var start, size, total int
		for k, dst := range map[string]*int{"startIndex": &start, "resultsPerPage": &size, "totalResults": &total} {
			if p[k] == nil || json.Unmarshal(p[k], dst) != nil {
				return lookup.ErrProtocol
			}
		}
		var rows []json.RawMessage
		if json.Unmarshal(p[spec.array], &rows) != nil || start != cursor.Start || size != len(rows) || total < 0 {
			return lookup.ErrProtocol
		}
		if cursor.Total >= 0 && cursor.Total != total {
			// Mutable offset pages cannot prove coverage when the total changes.
			cursor.Start = 0
			cursor.Total = -1
			cursor.Started = time.Now().UTC()
			b, _ := json.Marshal(cursor)
			if e = repo.CheckpointSync(ctx, lease, b, c.LeaseDuration); e != nil {
				return e
			}
			return fmt.Errorf("%w: source changed; next run restarts", lookup.ErrProtocol)
		}
		cursor.Total = total
		at := time.Now().UTC()
		for i, row := range rows {
			if stream == "cpe" {
				rec, e := nvd.DecodeProduct(row, at)
				if e != nil {
					return e
				}
				if _, e = repo.UpsertCPE(ctx, rec); e != nil {
					return e
				}
			} else {
				obj := row
				if spec.object != "" {
					var wrapper map[string]json.RawMessage
					if json.Unmarshal(row, &wrapper) != nil {
						return lookup.ErrProtocol
					}
					obj = wrapper[spec.object]
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(obj, &fields) != nil {
					return lookup.ErrProtocol
				}
				var id, modified string
				var sourceIDs []string
				if stream == "source" {
					if json.Unmarshal(fields["sourceIdentifiers"], &sourceIDs) != nil || len(sourceIDs) == 0 {
						return lookup.ErrProtocol
					}
				} else if json.Unmarshal(fields[spec.id], &id) != nil || id == "" {
					return lookup.ErrProtocol
				}
				if json.Unmarshal(fields[spec.modified], &modified) != nil {
					return lookup.ErrProtocol
				}
				mt, e := nvd.ParseTime(modified)
				if e != nil {
					return lookup.ErrProtocol
				}
				if stream == "match" {
					var cm string
					if json.Unmarshal(fields["cpeLastModified"], &cm) == nil {
						ct, e := nvd.ParseTime(cm)
						if e != nil {
							return lookup.ErrProtocol
						}
						if ct.After(mt) {
							mt = ct
						}
					}
				}
				if stream == "source" {
					for _, sourceID := range sourceIDs {
						if e = repo.UpsertSourceRecord(ctx, store.SourceRecord{Source: "nvd", Stream: stream, ID: sourceID, ModifiedAt: mt, FetchedAt: at, Raw: row}); e != nil {
							return e
						}
					}
				} else if e = repo.UpsertSourceRecord(ctx, store.SourceRecord{Source: "nvd", Stream: stream, ID: id, ModifiedAt: mt, FetchedAt: at, Raw: row}); e != nil {
					return e
				}
			}
			if i%100 == 0 {
				b, _ := json.Marshal(cursor)
				if e = repo.CheckpointSync(ctx, lease, b, c.LeaseDuration); e != nil {
					return e
				}
			}
		}
		cursor.Start += len(rows)
		b, _ := json.Marshal(cursor)
		if e = repo.CheckpointSync(ctx, lease, b, c.LeaseDuration); e != nil {
			return e
		}
		if cursor.Start >= total {
			if stream == "history" {
				end := cursor.WindowEnd
				if end.After(cursor.Started) {
					end = cursor.Started
				}
				if !end.Before(cursor.Started) {
					complete = true
					watermark = &cursor.Started
					return nil
				}
				cursor.WindowStart = end.Add(time.Millisecond)
				cursor.WindowEnd = cursor.WindowStart.Add(119 * 24 * time.Hour)
				cursor.Start = 0
				cursor.Total = -1
				b, _ := json.Marshal(cursor)
				if e = repo.CheckpointSync(ctx, lease, b, c.LeaseDuration); e != nil {
					return e
				}
				continue
			}
			complete = true
			watermark = &cursor.Started
			return nil
		}
		if len(rows) == 0 {
			return lookup.ErrProtocol
		}
	}
	return lookup.ErrPageLimit
}

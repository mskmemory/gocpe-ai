// Package lookup provides bounded external HTTP and auditable lookup results.
package lookup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"github.com/mskmemory/gocpe-ai/internal/store"
)

var ErrPageLimit = errors.New("lookup: page limit reached")
var ErrUnsupported = errors.New("lookup: unsupported ecosystem")
var ErrProtocol = errors.New("lookup: invalid response")

type Config struct {
	HTTPClient *http.Client
	Timeout    time.Duration
	MaxRetries int // zero means no retries
	Backoff    time.Duration
	MaxDelay   time.Duration
	MaxBytes   int64
}

type HTTP struct {
	client http.Client
	cfg    Config
}

func NewHTTP(c Config) *HTTP {
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Backoff <= 0 {
		c.Backoff = time.Second
	}
	if c.MaxDelay <= 0 {
		c.MaxDelay = time.Minute
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = 32 << 20
	}
	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	}
	if c.MaxRetries > 10 {
		c.MaxRetries = 10
	}
	client := http.Client{}
	if c.HTTPClient != nil {
		client = *c.HTTPClient
	}
	// Never forward credentials to redirects or silently change query methods.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTP{client: client, cfg: c}
}

type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("lookup: HTTP %d", e.Status) }

func (h *HTTP) Do(ctx context.Context, method, endpoint string, body []byte, headers http.Header) ([]byte, error) {
	var last error
	for attempt := 0; attempt <= h.cfg.MaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		requestCtx, cancel := context.WithTimeout(ctx, h.cfg.Timeout)
		req, err := http.NewRequestWithContext(requestCtx, method, endpoint, bytes.NewReader(body))
		if err != nil {
			cancel()
			return nil, errors.New("lookup: invalid endpoint")
		}
		req.Header = headers.Clone()
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := h.client.Do(req)
		delay := h.cfg.Backoff * time.Duration(1<<attempt)
		if delay > h.cfg.MaxDelay {
			delay = h.cfg.MaxDelay
		}
		delay = delay/2 + time.Duration(rand.Int64N(int64(delay/2)+1))
		retry := false
		var data []byte
		if err != nil {
			last = errors.New("lookup: transport failure")
			retry = true
		} else {
			data, err = io.ReadAll(io.LimitReader(resp.Body, h.cfg.MaxBytes+1))
			resp.Body.Close()
			if err != nil {
				last = errors.New("lookup: response read failure")
				retry = true
			} else if int64(len(data)) > h.cfg.MaxBytes {
				last = errors.New("lookup: response size limit")
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				cancel()
				return data, nil
			} else {
				last = &HTTPError{Status: resp.StatusCode}
				retry = resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode >= 500
			}
			if v := resp.Header.Get("Retry-After"); v != "" {
				if seconds, e := strconv.ParseInt(v, 10, 64); e == nil && seconds >= 0 && seconds < 86400*365 {
					if d := time.Duration(seconds) * time.Second; d > delay {
						delay = d
					}
				} else if t, e := http.ParseTime(v); e == nil && time.Until(t) > delay {
					delay = time.Until(t)
				}
			}
		}
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Do not retry earlier than Retry-After when it exceeds our wait budget.
		if !retry || attempt == h.cfg.MaxRetries || delay > h.cfg.MaxDelay {
			return nil, last
		}
		if err := Wait(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, last
}
func Wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type Observation struct {
	Evidence []store.Evidence
	Complete bool
	Reason   string
}

func (o *Observation) Add(source, endpoint, scope string, query any, raw []byte) {
	q, _ := json.Marshal(query)
	if !json.Valid(raw) {
		raw, _ = json.Marshal(map[string]string{"invalid_response": string(raw)})
	}
	o.Evidence = append(o.Evidence, store.Evidence{ID: store.NewID(), Source: source, ReferenceURL: endpoint, Query: q, ObservedAt: time.Now().UTC(), Scope: scope, MatchKind: "lookup", Snapshot: append(json.RawMessage(nil), raw...)})
}
func (o *Observation) Fail(err error) {
	o.Complete = false
	o.Reason = "LOOKUP_ERROR"
	if errors.Is(err, ErrPageLimit) {
		o.Reason = "LOOKUP_INCOMPLETE"
	}
	if errors.Is(err, ErrUnsupported) {
		o.Reason = "UNSUPPORTED_ECOSYSTEM"
	}
}

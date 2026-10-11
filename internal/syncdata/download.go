package syncdata

import (
	"context"
	"errors"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// DownloadArchive atomically replaces path only after a complete bounded
// download. Failed attempts use a temporary sibling; existing data is retained.
func DownloadArchive(ctx context.Context, endpoint, path string, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 16 << 30
	}
	client := http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		f, e := os.CreateTemp(filepath.Dir(path), ".osv-download-*")
		if e != nil {
			return e
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		req, e := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
		if e != nil {
			cancel()
			f.Close()
			os.Remove(f.Name())
			return errors.New("sync: invalid archive URL")
		}
		resp, e := client.Do(req)
		retry := true
		delay := time.Duration(1<<attempt) * time.Second
		if e != nil {
			last = errors.New("sync: archive transport failure")
		} else {
			if resp.StatusCode == http.StatusOK {
				n, ce := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
				last = ce
				if n > maxBytes {
					last = errors.New("sync: archive size limit")
					retry = false
				}
			} else {
				last = &lookup.HTTPError{Status: resp.StatusCode}
				retry = resp.StatusCode == 429 || resp.StatusCode >= 500
			}
			if seconds, se := strconv.Atoi(resp.Header.Get("Retry-After")); se == nil && seconds >= 0 {
				if seconds > 60 {
					retry = false
				} else if d := time.Duration(seconds) * time.Second; d > delay {
					delay = d
				}
			} else if until, te := http.ParseTime(resp.Header.Get("Retry-After")); te == nil {
				if d := time.Until(until); d > time.Minute {
					retry = false
				} else if d > delay {
					delay = d
				}
			}
			resp.Body.Close()
		}
		cancel()
		closeErr := f.Close()
		if last == nil {
			last = closeErr
		}
		if last == nil {
			if e = os.Rename(f.Name(), path); e != nil {
				os.Remove(f.Name())
				return e
			}
			return nil
		}
		os.Remove(f.Name())
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !retry || attempt == 3 {
			return last
		}
		if e = lookup.Wait(ctx, delay); e != nil {
			return e
		}
	}
	return last
}

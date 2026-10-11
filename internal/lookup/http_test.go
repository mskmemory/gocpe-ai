package lookup

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPPolicies(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		attempts int
		retry    string
	}{{"rate", 429, 3, "0"}, {"server", 503, 3, ""},
		{"requestTimeout", 408, 3, ""}, {"permanent", 400, 1, ""}, {"longRetry", 429, 1, "3600"}, {"dateRetry", 429, 1, time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)}} {
		t.Run(tc.name, func(t *testing.T) {
			var count atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				w.Header().Set("Retry-After", tc.retry)
				w.WriteHeader(tc.status)
			}))
			defer s.Close()
			_, e := NewHTTP(Config{MaxRetries: 2, Backoff: time.Millisecond, MaxDelay: 10 * time.Millisecond}).Do(context.Background(), "GET", s.URL, nil, nil)
			var he *HTTPError
			if !errors.As(e, &he) || int(count.Load()) != tc.attempts {
				t.Fatalf("%v calls %d", e, count.Load())
			}
		})
	}
	t.Run("cancel", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		_, e := NewHTTP(Config{}).Do(ctx, "GET", s.URL, nil, nil)
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal(e)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer s.Close()
		_, e := NewHTTP(Config{Timeout: 10 * time.Millisecond}).Do(context.Background(), "GET", s.URL, nil, nil)
		if e == nil {
			t.Fatal("expected timeout")
		}
	})
	t.Run("bodyReplay", func(t *testing.T) {
		n := 0
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			if string(b) != "{}" {
				t.Error("body lost")
			}
			n++
			if n == 1 {
				w.WriteHeader(503)
			} else {
				w.Write([]byte(`{}`))
			}
		}))
		defer s.Close()
		_, e := NewHTTP(Config{MaxRetries: 1, Backoff: time.Millisecond}).Do(context.Background(), "POST", s.URL, []byte(`{}`), nil)
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("size", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("12345")) }))
		defer s.Close()
		_, e := NewHTTP(Config{MaxBytes: 4}).Do(context.Background(), "GET", s.URL, nil, nil)
		if e == nil {
			t.Fatal("expected size error")
		}
	})
}

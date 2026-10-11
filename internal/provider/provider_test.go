package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var vendors = []string{"openai", "gemini", "claude", "deepseek"}

const validProposal = `{"aliases":["example"],"cpes":[{"value":"cpe:2.3:a:example:example:*:*:*:*:*:*:*:*","reason":"name"}],"purls":[{"value":"pkg:npm/example","reason":"name"}],"missing_fields":["version"]}`

func keys(t *testing.T) {
	t.Helper()
	for _, k := range []string{"OPENAI_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY"} {
		t.Setenv(k, "test-secret")
	}
}
func envelope(v, text, finish string) string {
	q, _ := json.Marshal(text)
	switch v {
	case "openai":
		return fmt.Sprintf(`{"status":%q,"output":[{"type":"message","content":[{"type":"output_text","text":%s}]}],"usage":{"input_tokens":11,"output_tokens":7}}`, finish, q)
	case "claude":
		return fmt.Sprintf(`{"stop_reason":%q,"content":[{"type":"text","text":%s}],"usage":{"input_tokens":11,"output_tokens":7}}`, finish, q)
	case "gemini":
		return fmt.Sprintf(`{"candidates":[{"finishReason":%q,"content":{"parts":[{"text":%s}]}}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":7}}`, finish, q)
	default:
		return fmt.Sprintf(`{"choices":[{"finish_reason":%q,"message":{"content":%s}}],"usage":{"prompt_tokens":11,"completion_tokens":7}}`, finish, q)
	}
}
func finish(v string) string {
	return map[string]string{"openai": "completed", "claude": "end_turn", "gemini": "STOP", "deepseek": "stop"}[v]
}
func setup(t *testing.T, v string, h http.HandlerFunc, cfg Config) AIProvider {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	cfg.Provider = v
	cfg.Model = "test-model"
	cfg.BaseURL = s.URL
	p, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestHTTPContracts(t *testing.T) {
	keys(t)
	for _, v := range vendors {
		t.Run(v, func(t *testing.T) {
			calls := 0
			p := setup(t, v, func(w http.ResponseWriter, r *http.Request) {
				calls++
				paths := map[string]string{"openai": "/responses", "claude": "/messages", "gemini": "/models/test-model:generateContent", "deepseek": "/chat/completions"}
				if r.Method != "POST" || r.URL.Path != paths[v] || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("request shape")
				}
				header, want := "Authorization", "Bearer test-secret"
				if v == "claude" {
					header, want = "x-api-key", "test-secret"
					if r.Header.Get("anthropic-version") != "2023-06-01" {
						t.Error("version")
					}
				}
				if v == "gemini" {
					header, want = "x-goog-api-key", "test-secret"
				}
				if r.Header.Get(header) != want {
					t.Error("authentication")
				}
				b, _ := io.ReadAll(r.Body)
				var body map[string]any
				if json.Unmarshal(b, &body) != nil {
					t.Error("body")
				}
				switch v {
				case "openai":
					if body["store"] != false || body["text"].(map[string]any)["format"].(map[string]any)["strict"] != true {
						t.Error("format")
					}
				case "claude":
					if body["output_config"] == nil {
						t.Error("format")
					}
				case "gemini":
					if body["generationConfig"].(map[string]any)["responseJsonSchema"] == nil {
						t.Error("schema")
					}
				case "deepseek":
					if body["response_format"].(map[string]any)["type"] != "json_object" || !strings.Contains(string(b), "JSON") {
						t.Error("json mode")
					}
				}
				response := validProposal
				if calls == 2 {
					response = `{"rankings":[{"candidate_id":"c1","evidence_ids":["e1"],"reason":"matches"}]}`
				}
				fmt.Fprint(w, envelope(v, response, finish(v)))
			}, Config{})
			got, e := p.Propose(context.Background(), ProposalRequest{Name: "example", Vendor: "example"})
			if e != nil || len(got.PURLs) != 1 {
				t.Fatalf("%+v %v", got, e)
			}
			if len(got.Metadata.Attempts) != 1 || got.Metadata.Attempts[0].Usage.InputTokens != 11 || got.Metadata.Attempts[0].Usage.OutputTokens != 7 {
				t.Fatal("usage")
			}
			rank, e := p.Rank(context.Background(), RankingRequest{Component: ProposalRequest{Name: "example"}, Candidates: []Candidate{{ID: "c1", Value: "pkg:npm/example", EvidenceIDs: []string{"e1"}}}})
			if e != nil || rank.Rankings[0].CandidateID != "c1" {
				t.Fatal(rank, e)
			}
		})
	}
}
func TestOutputFailures(t *testing.T) {
	keys(t)
	for _, v := range vendors {
		t.Run(v, func(t *testing.T) {
			cases := []struct {
				name, text, stop string
				want             ErrorKind
			}{
				{"empty", "", finish(v), Empty}, {"malformed", "{", finish(v), InvalidOutput}, {"unknown", `{"aliases":[],"cpes":[],"purls":[],"missing_fields":[],"confirmed":true}`, finish(v), InvalidOutput},
				{"null", `{"aliases":null,"cpes":[],"purls":[],"missing_fields":[]}`, finish(v), InvalidOutput},
				{"version", strings.Replace(validProposal, "pkg:npm/example", "pkg:npm/example@1.0", 1), finish(v), InvalidOutput},
				{"bad_cpe", strings.Replace(validProposal, "cpe:2.3:a:example:example:*:*:*:*:*:*:*:*", "not-cpe", 1), finish(v), InvalidOutput},
				{"truncated", validProposal, map[string]string{"openai": "incomplete", "claude": "max_tokens", "gemini": "MAX_TOKENS", "deepseek": "length"}[v], Truncated},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					p := setup(t, v, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, envelope(v, tc.text, tc.stop)) }, Config{})
					got, e := p.Propose(context.Background(), ProposalRequest{Name: "example"})
					if e == nil || kind(e) != tc.want || len(got.PURLs) != 0 || len(got.Metadata.Attempts) != 1 {
						t.Fatalf("got %v %v", got, e)
					}
				})
			}
		})
	}
}
func TestRefusal(t *testing.T) {
	keys(t)
	bodies := map[string]string{"openai": `{"status":"completed","output":[{"content":[{"type":"refusal","refusal":"secret"}]}]}`, "claude": envelope("claude", "secret", "refusal"), "gemini": `{"promptFeedback":{"blockReason":"SAFETY"}}`, "deepseek": envelope("deepseek", "secret", "content_filter")}
	for _, v := range vendors {
		p := setup(t, v, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, bodies[v]) }, Config{})
		_, e := p.Propose(context.Background(), ProposalRequest{Name: "example"})
		if e == nil || kind(e) != Refused || strings.Contains(e.Error(), "secret") {
			t.Fatal(v, e)
		}
	}
}
func TestRankingBoundaries(t *testing.T) {
	keys(t)
	for _, output := range []string{
		`{"rankings":[{"candidate_id":"unknown","evidence_ids":[],"reason":"x"}]}`,
		`{"rankings":[{"candidate_id":"c1","evidence_ids":["other"],"reason":"x"}]}`,
		`{"rankings":[{"candidate_id":"c1","evidence_ids":[],"reason":"x"},{"candidate_id":"c1","evidence_ids":[],"reason":"y"}]}`,
	} {
		p := setup(t, "openai", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, envelope("openai", output, "completed")) }, Config{})
		got, e := p.Rank(context.Background(), RankingRequest{Component: ProposalRequest{Name: "example"}, Candidates: []Candidate{{ID: "c1", Value: "x"}}})
		if e == nil || kind(e) != InvalidOutput || len(got.Rankings) != 0 {
			t.Fatal(got, e)
		}
	}
}
func TestRetriesAndCancellation(t *testing.T) {
	keys(t)
	for _, status := range []int{429, 503, 401, 400} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var count atomic.Int32
			p := setup(t, "openai", func(w http.ResponseWriter, r *http.Request) {
				if count.Add(1) == 1 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					fmt.Fprint(w, "test-secret")
					return
				}
				fmt.Fprint(w, envelope("openai", validProposal, "completed"))
			}, Config{MaxRetries: 1})
			got, e := p.Propose(context.Background(), ProposalRequest{Name: "example"})
			if status == 429 || status == 503 {
				if e != nil || len(got.Metadata.Attempts) != 2 {
					t.Fatal(got, e)
				}
			} else if e == nil || count.Load() != 1 || strings.Contains(e.Error(), "test-secret") {
				t.Fatal(e)
			}
		})
	}
	p := setup(t, "openai", func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "120"); w.WriteHeader(429) }, Config{MaxRetries: 3, Timeout: 30 * time.Millisecond})
	_, e := p.Propose(context.Background(), ProposalRequest{Name: "example"})
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = p.Propose(ctx, ProposalRequest{Name: "example"})
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestLimitsRedirectAndConcurrentUse(t *testing.T) {
	keys(t)
	var leaked atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer destination.Close()
	p := setup(t, "claude", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }, Config{})
	_, e := p.Propose(context.Background(), ProposalRequest{Name: "example"})
	if e == nil || leaked.Load() {
		t.Fatal("redirect followed")
	}
	p = setup(t, "openai", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", (1<<20)+1)) }, Config{})
	_, e = p.Propose(context.Background(), ProposalRequest{Name: "example"})
	if e == nil || kind(e) != InvalidOutput {
		t.Fatal(e)
	}
	p = setup(t, "openai", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, envelope("openai", validProposal, "completed"))
	}, Config{})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := p.Propose(context.Background(), ProposalRequest{Name: "example"}); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
}
func TestConfigAndInput(t *testing.T) {
	keys(t)
	for _, cfg := range []Config{{Provider: "other", Model: "x"}, {Provider: "openai"}, {Provider: "openai", Model: "x", MaxRetries: 4}, {Provider: "gemini", Model: "../x"}, {Provider: "claude", Model: "x", BaseURL: "http://example.com"}} {
		if _, e := New(cfg); e == nil {
			t.Fatal("accepted bad config")
		}
	}
	t.Setenv("OPENAI_API_KEY", "")
	if _, e := New(Config{Provider: "openai", Model: "x"}); e == nil {
		t.Fatal("missing key")
	}
}

func TestRetryExhaustionAndInFlightTimeout(t *testing.T) {
	keys(t)
	var count atomic.Int32
	p := setup(t, "deepseek", func(w http.ResponseWriter, r *http.Request) { count.Add(1); w.WriteHeader(429) }, Config{MaxRetries: 1})
	out, e := p.Propose(context.Background(), ProposalRequest{Name: "example"})
	if e == nil || kind(e) != RateLimited || count.Load() != 2 || len(out.Metadata.Attempts) != 2 {
		t.Fatal(out, e)
	}
	p = setup(t, "gemini", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}, Config{Timeout: 20 * time.Millisecond})
	_, e = p.Propose(context.Background(), ProposalRequest{Name: "example"})
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
}
func TestNoEvidenceIsSuccessfulEmptyProposal(t *testing.T) {
	keys(t)
	for _, v := range vendors {
		p := setup(t, v, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, envelope(v, `{"aliases":[],"cpes":[],"purls":[],"missing_fields":["ecosystem"]}`, finish(v)))
		}, Config{})
		out, e := p.Propose(context.Background(), ProposalRequest{Name: "example"})
		if e != nil || out.Aliases == nil {
			t.Fatal(out, e)
		}
	}
}
func TestSchemaLimitsAndEnvironment(t *testing.T) {
	keys(t)
	t.Setenv("OPENAI_MODEL", "configured-model")
	if _, e := NewFromEnv(Config{Provider: "openai"}); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{
		`{"aliases":["a","b","c","d","e","f"],"cpes":[],"purls":[],"missing_fields":[]}`,
		`{"aliases":["a","a"],"cpes":[],"purls":[],"missing_fields":[]}`,
		`{"aliases":[],"cpes":[],"purls":[]}`,
		validProposal + `{}`,
	} {
		var out ProposalResponse
		if validate(raw, proposalSchema, &out) == nil {
			t.Fatal("invalid schema accepted")
		}
	}
	if d := retryDelay(time.Now().Add(time.Minute).UTC().Format(http.TimeFormat), 0); d < 58*time.Second {
		t.Fatal(d)
	}
}

func TestEmptyHTTPBodyAndMissingUsage(t *testing.T) {
	keys(t)
	for _, v := range vendors {
		p := setup(t, v, func(w http.ResponseWriter, r *http.Request) {}, Config{})
		_, e := p.Propose(context.Background(), ProposalRequest{Name: "example"})
		if e == nil || kind(e) != Empty {
			t.Fatal(v, e)
		}
	}
	_, u, e := decode("openai", []byte(`{"status":"completed","output":[{"content":[{"type":"output_text","text":"{}"}]}]}`))
	if e != nil || u.Known {
		t.Fatal(u, e)
	}
}

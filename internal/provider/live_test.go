//go:build live

package provider

import (
	"context"
	"os"
	"testing"
)

// Explicit provider selection prevents accidentally billing all configured accounts.
func TestLive(t *testing.T) {
	v := os.Getenv("GOCPE_LIVE_PROVIDER")
	model := os.Getenv("GOCPE_LIVE_MODEL")
	if v == "" || model == "" {
		t.Skip("未検証: GOCPE_LIVE_PROVIDER / GOCPE_LIVE_MODEL not configured")
	}
	env := map[string]string{"openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY", "claude": "ANTHROPIC_API_KEY", "deepseek": "DEEPSEEK_API_KEY"}[v]
	if env == "" {
		t.Fatal("invalid provider")
	}
	if os.Getenv(env) == "" {
		t.Skip("未検証: credential missing")
	}
	p, e := New(Config{Provider: v, Model: model})
	if e != nil {
		t.Fatal(e)
	}
	out, e := p.Propose(context.Background(), ProposalRequest{Name: "requests", Hints: map[string]string{"ecosystem": "PyPI"}})
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Metadata.Attempts) != 1 {
		t.Fatal("missing attempt")
	}
	_, e = p.Rank(context.Background(), RankingRequest{Component: ProposalRequest{Name: "requests"}, Candidates: []Candidate{{ID: "one", Value: "pkg:pypi/requests", EvidenceIDs: []string{}}}})
	if e != nil {
		t.Fatal(e)
	}
}

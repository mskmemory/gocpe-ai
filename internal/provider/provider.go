// Package provider generates unverified identifier proposals; it never makes
// external verification or acceptance decisions.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type AIProvider interface {
	Propose(context.Context, ProposalRequest) (ProposalResponse, error)
	Rank(context.Context, RankingRequest) (RankingResponse, error)
}
type ProposalRequest struct {
	Name    string            `json:"name"`
	Vendor  string            `json:"vendor"`
	Version string            `json:"version"`
	Hints   map[string]string `json:"hints,omitempty"`
}
type Candidate struct {
	ID          string   `json:"id"`
	Value       string   `json:"value"`
	EvidenceIDs []string `json:"evidence_ids"`
}
type RankingRequest struct {
	Component  ProposalRequest `json:"component"`
	Candidates []Candidate     `json:"candidates"`
}
type Proposal struct {
	Value  string `json:"value"`
	Reason string `json:"reason"`
}
type ProposalResponse struct {
	Aliases       []string   `json:"aliases"`
	CPEs          []Proposal `json:"cpes"`
	PURLs         []Proposal `json:"purls"`
	MissingFields []string   `json:"missing_fields"`
	Metadata      Metadata   `json:"-"`
}
type RankedCandidate struct {
	CandidateID string   `json:"candidate_id"`
	EvidenceIDs []string `json:"evidence_ids"`
	Reason      string   `json:"reason"`
}
type RankingResponse struct {
	Rankings []RankedCandidate `json:"rankings"`
	Metadata Metadata          `json:"-"`
}

// Usage is provider-reported, not a cost estimate. Missing usage is unknown.
type Usage struct {
	Known                                                                              bool
	InputTokens, OutputTokens, CachedInputTokens, CacheCreationTokens, ReasoningTokens int64
}
type Attempt struct {
	Number     int
	HTTPStatus int
	Usage      Usage
	Outcome    ErrorKind
	StartedAt  time.Time
	Duration   time.Duration
}

// Metadata is returned even on failure. Persist every attempt: retries can bill twice.
type Metadata struct {
	Provider, Model, PromptVersion string
	Attempts                       []Attempt
}
type ErrorKind string

const (
	InvalidInput  ErrorKind = "invalid_input"
	InvalidOutput ErrorKind = "invalid_output"
	Refused       ErrorKind = "refused"
	Empty         ErrorKind = "empty_response"
	Truncated     ErrorKind = "truncated"
	RateLimited   ErrorKind = "rate_limited"
	Unauthorized  ErrorKind = "unauthorized"
	Unsupported   ErrorKind = "unsupported"
	Unavailable   ErrorKind = "unavailable"
	Cancelled     ErrorKind = "cancelled"
	Timeout       ErrorKind = "timeout"
)

type Error struct {
	Kind   ErrorKind
	Status int
	cause  error
}

func (e *Error) Error() string  { return fmt.Sprintf("AI provider: %s (HTTP %d)", e.Kind, e.Status) }
func (e *Error) Unwrap() error  { return e.cause }
func failure(k ErrorKind) error { return &Error{Kind: k} }
func kind(err error) ErrorKind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Unavailable
}

// Config never contains a credential. New reads the provider's standard API-key
// environment variable once. Observe receives only safe counters, never payloads.
// Observe may run concurrently and must be fast, concurrency-safe and non-blocking.
type Config struct {
	Provider        string
	Model           string
	BaseURL         string
	HTTPClient      *http.Client
	Timeout         time.Duration // entire operation, including retries
	MaxRetries      int           // 0..3; no retries by default
	MaxOutputTokens int
	Observe         func(Attempt)
}
type client struct {
	cfg       Config
	key, base string
	http      *http.Client
}

var modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

func New(cfg Config) (AIProvider, error) {
	env, base := "", ""
	switch cfg.Provider {
	case "openai":
		env, base = "OPENAI_API_KEY", "https://api.openai.com/v1"
	case "gemini":
		env, base = "GEMINI_API_KEY", "https://generativelanguage.googleapis.com/v1beta"
	case "claude":
		env, base = "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1"
	case "deepseek":
		env, base = "DEEPSEEK_API_KEY", "https://api.deepseek.com"
	default:
		return nil, failure(Unsupported)
	}
	key := os.Getenv(env)
	if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\r\n") || !modelPattern.MatchString(cfg.Model) || cfg.MaxRetries < 0 || cfg.MaxRetries > 3 {
		return nil, failure(InvalidInput)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.Timeout < 0 || cfg.Timeout > 10*time.Minute {
		return nil, failure(InvalidInput)
	}
	if cfg.MaxOutputTokens == 0 {
		cfg.MaxOutputTokens = 4096
	}
	if cfg.MaxOutputTokens < 1 || cfg.MaxOutputTokens > 32768 {
		return nil, failure(InvalidInput)
	}
	if cfg.BaseURL != "" {
		base = strings.TrimRight(cfg.BaseURL, "/")
	}
	u, e := url.Parse(base)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))) {
		return nil, failure(InvalidInput)
	}
	hc := http.Client{}
	if cfg.HTTPClient != nil {
		hc = *cfg.HTTPClient
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client{cfg: cfg, key: key, base: base, http: &hc}, nil
}
func validInput(req ProposalRequest) bool {
	if strings.TrimSpace(req.Name) == "" {
		return false
	}
	b, e := json.Marshal(req)
	return e == nil && len(b) <= 16384
}
func (c *client) Propose(ctx context.Context, req ProposalRequest) (ProposalResponse, error) {
	out := ProposalResponse{}
	if !validInput(req) {
		return out, failure(InvalidInput)
	}
	raw, meta, err := c.call(ctx, "propose", req, proposalSchema)
	out.Metadata = meta
	if err != nil {
		return out, err
	}
	if err = validate(raw, proposalSchema, &out); err == nil {
		err = validateProposals(out, req.Version)
	}
	out.Metadata = meta
	if err != nil {
		return ProposalResponse{Metadata: meta}, err
	}
	return out, nil
}
func (c *client) Rank(ctx context.Context, req RankingRequest) (RankingResponse, error) {
	out := RankingResponse{}
	allowed := map[string]map[string]bool{}
	if !validInput(req.Component) || len(req.Candidates) == 0 || len(req.Candidates) > 50 {
		return out, failure(InvalidInput)
	}
	for _, v := range req.Candidates {
		if strings.TrimSpace(v.ID) == "" || len(v.ID) > 200 || allowed[v.ID] != nil || len(v.Value) > 4096 || len(v.EvidenceIDs) > 20 {
			return out, failure(InvalidInput)
		}
		allowed[v.ID] = map[string]bool{}
		for _, id := range v.EvidenceIDs {
			if id == "" || len(id) > 200 {
				return out, failure(InvalidInput)
			}
			allowed[v.ID][id] = true
		}
	}
	raw, meta, err := c.call(ctx, "rank", req, rankingSchema)
	out.Metadata = meta
	if err != nil {
		return out, err
	}
	if err = validate(raw, rankingSchema, &out); err != nil {
		return RankingResponse{Metadata: meta}, err
	}
	seen := map[string]bool{}
	for _, v := range out.Rankings {
		if allowed[v.CandidateID] == nil || seen[v.CandidateID] {
			return RankingResponse{Metadata: meta}, failure(InvalidOutput)
		}
		seen[v.CandidateID] = true
		for _, id := range v.EvidenceIDs {
			if !allowed[v.CandidateID][id] {
				return RankingResponse{Metadata: meta}, failure(InvalidOutput)
			}
		}
	}
	out.Metadata = meta
	return out, nil
}

// NewFromEnv reads PROVIDER_MODEL when Config.Model is empty. Explicit Config
// values take precedence. It does not auto-select or fall back to another model.
func NewFromEnv(cfg Config) (AIProvider, error) {
	if cfg.Model == "" {
		name := map[string]string{"openai": "OPENAI_MODEL", "gemini": "GEMINI_MODEL", "claude": "ANTHROPIC_MODEL", "deepseek": "DEEPSEEK_MODEL"}[cfg.Provider]
		if name != "" {
			cfg.Model = os.Getenv(name)
		}
	}
	return New(cfg)
}

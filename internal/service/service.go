package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func ValidID(id string) bool { return uuidPattern.MatchString(id) }
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type Config struct {
	Store     Store
	Providers map[Provider][]string
	CursorKey []byte
	Now       func() time.Time
}
type Service struct {
	store     Store
	providers map[Provider][]string
	key       []byte
	now       func() time.Time
	validator *Validator
}

func New(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if len(cfg.CursorKey) < 32 {
		return nil, fmt.Errorf("cursor key must be at least 32 bytes")
	}
	v, err := NewValidator()
	if err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Service{store: cfg.Store, providers: map[Provider][]string{}, key: append([]byte(nil), cfg.CursorKey...), now: cfg.Now, validator: v}
	for p, ms := range cfg.Providers {
		if p != "openai" && p != "gemini" && p != "claude" && p != "deepseek" {
			return nil, fmt.Errorf("unknown provider")
		}
		for _, m := range ms {
			if strings.TrimSpace(m) == "" {
				return nil, fmt.Errorf("empty model")
			}
		}
		s.providers[p] = append([]string(nil), ms...)
	}
	return s, nil
}
func (s *Service) Providers() ProviderList {
	p := ProviderList{Items: []ProviderInfo{}}
	for k, v := range s.providers {
		if len(v) > 0 {
			p.Items = append(p.Items, ProviderInfo{Provider: k, Models: append([]string(nil), v...)})
		}
	}
	sort.Slice(p.Items, func(i, j int) bool { return p.Items[i].Provider < p.Items[j].Provider })
	return p
}
func (s *Service) Create(ctx context.Context, owner, entry, key string, raw []byte) (Job, error) {
	if err := ctx.Err(); err != nil {
		return Job{}, err
	}
	if owner == "" {
		return Job{}, &Fault{Status: 401, Code: "UNAUTHENTICATED", Message: "Authentication required"}
	}
	if len(key) > 128 || strings.TrimSpace(key) != key {
		return Job{}, Invalid("", "Invalid Idempotency-Key")
	}
	for _, ch := range key {
		if ch < 33 || ch > 126 {
			return Job{}, Invalid("", "Idempotency-Key must contain visible ASCII characters")
		}
	}
	p, err := s.validator.Prepare(entry, raw)
	if err != nil {
		return Job{}, err
	}
	o := p.Options
	allowed := false
	for _, m := range s.providers[o.Provider] {
		if m == o.Model {
			allowed = true
		}
	}
	if !allowed {
		if len(s.providers) == 0 {
			return Job{}, Unavailable()
		}
		return Job{}, &Fault{Status: 422, Code: "MODEL_NOT_ALLOWED", Message: "Provider/model is not enabled"}
	}
	now := s.now().UTC()
	j := Job{ID: NewID(), Status: "queued", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour), Options: o, Errors: []Error{}, RunMetadata: RunMetadata{InputSHA256: digest(p.Canonical), ConfigSHA256: hashValue(o), PromptVersion: "not-configured", RuleVersion: "v1", SchemaVersion: "1", Entrypoint: entry}}
	j.Progress.Total = len(p.Components)
	a := Admission{OwnerID: owner, Job: j, InputKind: p.Kind, InputDocument: append(json.RawMessage(nil), raw...), Components: p.Components, IdempotencyKey: key, RequestHash: hashValue(struct {
		Entry string
		Body  json.RawMessage
	}{entry, p.Canonical}), KeyExpiresAt: now.Add(24 * time.Hour)}
	stored, err := s.store.Admit(ctx, a)
	if err != nil {
		return Job{}, err
	}
	return s.visible(owner, stored)
}
func (s *Service) visible(owner string, v StoredJob) (Job, error) {
	if v.OwnerID != owner || !v.Job.ExpiresAt.After(s.now()) {
		return Job{}, ErrNotFound
	}
	return v.Job, nil
}
func (s *Service) Get(ctx context.Context, owner, id string) (Job, error) {
	if !ValidID(id) {
		return Job{}, ErrNotFound
	}
	v, err := s.store.GetJob(ctx, owner, id, s.now())
	if err != nil {
		return Job{}, err
	}
	return s.visible(owner, v)
}
func Terminal(status string) bool {
	return status == "completed" || status == "partial" || status == "failed" || status == "cancelled"
}
func (s *Service) Cancel(ctx context.Context, owner, id string) (Job, bool, error) {
	_, err := s.Get(ctx, owner, id)
	if err != nil {
		return Job{}, false, err
	}
	v, accepted, err := s.store.Cancel(ctx, owner, id, s.now())
	if err != nil {
		return Job{}, false, err
	}
	j, err := s.visible(owner, v)
	return j, accepted, err
}
func (s *Service) Results(ctx context.Context, owner, id, token string, limit int) (ResultPage, error) {
	j, err := s.Get(ctx, owner, id)
	if err != nil {
		return ResultPage{}, err
	}
	if !Terminal(j.Status) {
		return ResultPage{}, &Fault{Status: 409, Code: "RESULTS_NOT_READY", Message: "Results are available after the job terminates"}
	}
	id = j.ID
	n, err := pageLimit(limit)
	if err != nil {
		return ResultPage{}, err
	}
	scope := hashValue([]string{"results", owner, id})
	after, err := s.readCursor(token, scope)
	if err != nil {
		return ResultPage{}, err
	}
	rows, err := s.store.Results(ctx, owner, id, PageQuery{Limit: n + 1, After: after}, s.now())
	if err != nil {
		return ResultPage{}, err
	}
	out := ResultPage{JobID: id, SchemaVersion: "1", Items: rows}
	if len(rows) > n {
		out.Items = rows[:n]
		until := s.now().Add(time.Hour)
		if j.ExpiresAt.Before(until) {
			until = j.ExpiresAt
		}
		out.NextCursor = s.sign(scope, strconv.Itoa(rows[n-1].Ordinal), until)
	}
	if out.Items == nil {
		out.Items = []ComponentResult{}
	}
	return out, nil
}
func (s *Service) CPEs(ctx context.Context, owner, token string, q CPEQuery) (CPEPage, error) {
	n, err := pageLimit(q.Limit)
	if err != nil {
		return CPEPage{}, err
	}
	q.PageQuery = PageQuery{}
	scope := hashValue(struct {
		Owner, Kind string
		Query       CPEQuery
	}{owner, "cpes", q})
	after, err := s.readCursor(token, scope)
	if err != nil {
		return CPEPage{}, err
	}
	q.PageQuery = PageQuery{n + 1, after}
	rows, err := s.store.CPEs(ctx, q)
	if err != nil {
		return CPEPage{}, err
	}
	out := CPEPage{Items: rows, Coverage: "local_only"}
	if len(rows) > n {
		out.Items = rows[:n]
		out.NextCursor = s.sign(scope, rows[n-1].CPENameID, s.now().Add(time.Hour))
	}
	if out.Items == nil {
		out.Items = []CPE{}
	}
	return out, nil
}
func (s *Service) PURLs(ctx context.Context, owner, token string, q PURLQuery) (PURLPage, error) {
	n, err := pageLimit(q.Limit)
	if err != nil {
		return PURLPage{}, err
	}
	q.PageQuery = PageQuery{}
	scope := hashValue(struct {
		Owner, Kind string
		Query       PURLQuery
	}{owner, "purls", q})
	after, err := s.readCursor(token, scope)
	if err != nil {
		return PURLPage{}, err
	}
	q.PageQuery = PageQuery{n + 1, after}
	rows, err := s.store.PURLs(ctx, q)
	if err != nil {
		return PURLPage{}, err
	}
	out := PURLPage{Items: rows, Coverage: "local_only"}
	if len(rows) > n {
		out.Items = rows[:n]
		out.NextCursor = s.sign(scope, rows[n-1].ID, s.now().Add(time.Hour))
	}
	if out.Items == nil {
		out.Items = []PURL{}
	}
	return out, nil
}

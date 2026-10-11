// Package testutil provides fixtures for tests only. The executable never uses it.
package testutil

import (
	"context"
	"encoding/json"
	"github.com/mskmemory/gocpe-ai/internal/service"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type key struct{ Owner, Key string }
type MemoryStore struct {
	mu          sync.Mutex
	jobs        map[string]service.Admission
	keys        map[key]string
	results     map[string][]service.ComponentResult
	CPERecords  []service.CPE
	PURLRecords []service.PURL
	Ready       bool
}

func NewStore() *MemoryStore {
	return &MemoryStore{jobs: map[string]service.Admission{}, keys: map[key]string{}, results: map[string][]service.ComponentResult{}, Ready: true}
}
func clone[T any](v T) T {
	b, _ := json.Marshal(v)
	var copy T
	_ = json.Unmarshal(b, &copy)
	return copy
}
func (m *MemoryStore) Admit(ctx context.Context, a service.Admission) (service.StoredJob, error) {
	if err := ctx.Err(); err != nil {
		return service.StoredJob{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key{a.OwnerID, a.IdempotencyKey}
	if a.IdempotencyKey != "" {
		if id, ok := m.keys[k]; ok {
			old := m.jobs[id]
			if old.KeyExpiresAt.After(a.Job.CreatedAt) {
				if old.RequestHash != a.RequestHash {
					return service.StoredJob{}, service.ErrConflict
				}
				return service.StoredJob{OwnerID: old.OwnerID, Job: clone(old.Job)}, nil
			}
		}
	}
	if !m.Ready {
		return service.StoredJob{}, service.ErrUnavailable
	}
	m.jobs[a.Job.ID] = clone(a)
	if a.IdempotencyKey != "" {
		m.keys[k] = a.Job.ID
	}
	return service.StoredJob{OwnerID: a.OwnerID, Job: clone(a.Job)}, nil
}
func (m *MemoryStore) get(owner, id string, now time.Time) (service.Admission, error) {
	a, ok := m.jobs[id]
	if !ok || a.OwnerID != owner || !a.Job.ExpiresAt.After(now) {
		return a, service.ErrNotFound
	}
	return a, nil
}
func (m *MemoryStore) GetJob(ctx context.Context, owner, id string, now time.Time) (service.StoredJob, error) {
	if err := ctx.Err(); err != nil {
		return service.StoredJob{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a, e := m.get(owner, id, now)
	return service.StoredJob{OwnerID: a.OwnerID, Job: clone(a.Job)}, e
}
func (m *MemoryStore) Cancel(ctx context.Context, owner, id string, now time.Time) (service.StoredJob, bool, error) {
	if err := ctx.Err(); err != nil {
		return service.StoredJob{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a, e := m.get(owner, id, now)
	if e != nil {
		return service.StoredJob{}, false, e
	}
	accepted := !service.Terminal(a.Job.Status)
	switch a.Job.Status {
	case "queued":
		a.Job.Status = "cancelled"
	case "running":
		a.Job.Status = "cancelling"
	}
	if accepted {
		a.Job.UpdatedAt = now
		m.jobs[id] = a
	}
	return service.StoredJob{OwnerID: a.OwnerID, Job: clone(a.Job)}, accepted, nil
}
func (m *MemoryStore) Results(ctx context.Context, owner, id string, q service.PageQuery, now time.Time) ([]service.ComponentResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, e := m.get(owner, id, now); e != nil {
		return nil, e
	}
	after := -1
	if q.After != "" {
		after, _ = strconv.Atoi(q.After)
	}
	out := []service.ComponentResult{}
	for _, r := range m.results[id] {
		if r.Ordinal > after {
			out = append(out, clone(r))
			if len(out) == q.Limit {
				break
			}
		}
	}
	return out, nil
}
func (m *MemoryStore) CPEs(ctx context.Context, q service.CPEQuery) ([]service.CPE, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []service.CPE{}
	for _, r := range m.CPERecords {
		if r.CPENameID <= q.After || r.Deprecated != q.Deprecated || (q.Vendor != "" && r.Vendor != q.Vendor) || (q.Product != "" && r.Product != q.Product) {
			continue
		}
		if q.Q != "" && !strings.Contains(strings.ToLower(r.CPEName+" "+strings.Join(r.Titles, " ")), strings.ToLower(q.Q)) {
			continue
		}
		out = append(out, clone(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CPENameID < out[j].CPENameID })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (m *MemoryStore) PURLs(ctx context.Context, q service.PURLQuery) ([]service.PURL, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []service.PURL{}
	for _, r := range m.PURLRecords {
		if len(r.OSVRecordIDs) == 0 || r.ID <= q.After || (q.Type != "" && r.Type != q.Type) || (q.Namespace != "" && r.Namespace != q.Namespace) || (q.Name != "" && r.Name != q.Name) {
			continue
		}
		if q.Q != "" && !strings.Contains(strings.ToLower(r.CanonicalPURL), strings.ToLower(q.Q)) {
			continue
		}
		out = append(out, clone(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (m *MemoryStore) Finish(id, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.jobs[id]
	a.Job.Status = status
	a.Job.Progress.Processed = a.Job.Progress.Total
	m.jobs[id] = a
	rs := []service.ComponentResult{}
	for _, c := range a.Components {
		rs = append(rs, service.ComponentResult{ComponentID: c.Package.ID, Ordinal: c.Ordinal, SourcePointer: c.SourcePointer, Input: c.Package, Errors: []service.Error{}})
	}
	m.results[id] = rs
}
func (m *MemoryStore) SetStatus(id, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.jobs[id]
	a.Job.Status = status
	m.jobs[id] = a
}
func (m *MemoryStore) SetReady(ready bool) { m.mu.Lock(); defer m.mu.Unlock(); m.Ready = ready }
func (m *MemoryStore) Admission(id string) service.Admission {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clone(m.jobs[id])
}

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mskmemory/gocpe-ai/internal/store"
)

const jobColumns = `j.id::text, j.owner_id, j.status, j.provider, j.model, j.input_kind, j.options,
    j.run_metadata, j.errors, j.input_sha256, j.config_sha256, j.total, j.processed, j.attempts,
    j.created_at, j.updated_at, j.finished_at, j.expires_at, j.deadline`

func scanJob(row pgx.Row) (store.Job, error) {
	var j store.Job
	var status string
	err := row.Scan(&j.ID, &j.Owner, &status, &j.Provider, &j.Model, &j.InputKind, &j.Options,
		&j.RunMetadata, &j.Errors, &j.InputSHA256, &j.ConfigSHA256, &j.Total, &j.Processed, &j.Attempts,
		&j.CreatedAt, &j.UpdatedAt, &j.FinishedAt, &j.ExpiresAt, &j.Deadline)
	j.Status = store.JobStatus(status)
	return j, err
}

// requestHash is the idempotency fingerprint: endpoint + canonical JSON of
// the original (pre-default) request body.
func requestHash(endpoint store.Endpoint, request []byte) (string, error) {
	c, err := canonicalJSON(request)
	if err != nil {
		return "", err
	}
	return sha256Hex(append([]byte(string(endpoint)+"\n"), c...)), nil
}

func validateNewJob(j store.NewJob) error {
	switch {
	case strings.TrimSpace(j.Owner) == "":
		return fmt.Errorf("%w: owner is required", store.ErrInvalid)
	case j.Endpoint != store.EndpointResolution && j.Endpoint != store.EndpointPackageSearch:
		return fmt.Errorf("%w: unknown endpoint", store.ErrInvalid)
	case len(j.IdempotencyKey) > 128:
		return fmt.Errorf("%w: idempotency key longer than 128", store.ErrInvalid)
	case len(j.Components) < 1 || len(j.Components) > 1000:
		return fmt.Errorf("%w: 1..1000 components required", store.ErrInvalid)
	case !isObject(j.Input):
		return fmt.Errorf("%w: input document must be a JSON object", store.ErrInvalid)
	case !isObject(j.Options):
		return fmt.Errorf("%w: options must be a JSON object", store.ErrInvalid)
	}
	ids := make(map[string]bool, len(j.Components))
	for _, c := range j.Components {
		if c.ID == "" || ids[c.ID] {
			return fmt.Errorf("%w: component ids must be unique and non-empty", store.ErrInvalid)
		}
		ids[c.ID] = true
		if !isObject(c.Input) {
			return fmt.Errorf("%w: component input must be a JSON object", store.ErrInvalid)
		}
		if len(c.Raw) > 0 && !isObject(c.Raw) {
			return fmt.Errorf("%w: component raw values must be a JSON object", store.ErrInvalid)
		}
	}
	return nil
}

// CreateJob accepts a job atomically with its components and idempotency key.
// Concurrent requests with the same owner+key serialize on the key's primary
// key; exactly one job survives and the others return it (or conflict).
func (s *Store) CreateJob(ctx context.Context, nj store.NewJob) (store.Job, bool, error) {
	return s.CreateJobIfReady(ctx, nj, true)
}

// CreateJobIfReady allows replay while rejecting new work when no worker is ready.
func (s *Store) CreateJobIfReady(ctx context.Context, nj store.NewJob, ready bool) (store.Job, bool, error) {
	if s.cfg.Retention <= s.cfg.ExecutionTimeout || s.cfg.Retention < s.cfg.IdempotencyTTL {
		return store.Job{}, false, store.ErrInvalid
	}
	if err := validateNewJob(nj); err != nil {
		return store.Job{}, false, err
	}
	reqHash := ""
	if nj.IdempotencyKey != "" {
		var err error
		if reqHash, err = requestHash(nj.Endpoint, nj.Request); err != nil {
			return store.Job{}, false, err
		}
		// Fast path for replays: avoid inserting a job that will be discarded.
		if job, ok, err := s.replay(ctx, nj.Owner, nj.IdempotencyKey, reqHash); err != nil || ok {
			return job, false, err
		}
	}
	if !ready {
		return store.Job{}, false, store.ErrWorkerUnavailable
	}
	inputCanon, err := canonicalJSON(nj.Input)
	if err != nil {
		return store.Job{}, false, err
	}
	optionsCanon, err := canonicalJSON(nj.Options)
	if err != nil {
		return store.Job{}, false, err
	}
	meta, err := objectOrEmpty(nj.RunMetadata)
	if err != nil {
		return store.Job{}, false, err
	}
	inputHash, configHash := sha256Hex(inputCanon), sha256Hex(optionsCanon)
	jobID := store.NewID()

	var job store.Job
	created := true
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
INSERT INTO resolution_jobs AS j (id, owner_id, status, provider, model, options, input_kind, input_document,
    input_sha256, config_sha256, run_metadata, total, created_at, updated_at, expires_at, deadline)
VALUES ($1, $2, 'queued', $3, $4, $5::jsonb, $6, $7::jsonb, $8::text, $9::text,
    $10::jsonb || jsonb_build_object('input_sha256', $8::text, 'config_sha256', $9::text, 'entrypoint', $11::text),
    $12, now(), now(), now() + $13 * interval '1 microsecond', now() + $14 * interval '1 microsecond')
RETURNING `+jobColumns,
			jobID, nj.Owner, nj.Provider, nj.Model, string(nj.Options), nj.InputKind, string(nj.Input),
			inputHash, configHash, string(meta), string(nj.Endpoint), len(nj.Components),
			micros(s.cfg.Retention), micros(s.cfg.ExecutionTimeout))
		var err error
		if job, err = scanJob(row); err != nil {
			return err
		}
		batch := &pgx.Batch{}
		for i, c := range nj.Components {
			raw := c.Raw
			if len(raw) == 0 {
				raw = json.RawMessage("{}")
			}
			batch.Queue(`INSERT INTO resolution_components (job_id, component_id, ordinal, source_pointer, normalized_input, raw_values)
VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb)`, jobID, c.ID, i, c.SourcePointer, string(c.Input), string(raw))
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return err
		}
		if nj.IdempotencyKey == "" {
			return nil
		}
		// Take over the key only if it is absent or expired. A live key
		// leaves this statement without a row: roll back our job and replay.
		var keyJob string
		err = tx.QueryRow(ctx, `
INSERT INTO idempotency_keys (owner_id, key, request_sha256, job_id, created_at, expires_at)
VALUES ($1, $2, $3, $4, now(), now() + $5 * interval '1 microsecond')
ON CONFLICT (owner_id, key) DO UPDATE SET
    request_sha256 = EXCLUDED.request_sha256, job_id = EXCLUDED.job_id,
    created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at
WHERE idempotency_keys.expires_at <= now()
RETURNING job_id::text`, nj.Owner, nj.IdempotencyKey, reqHash, jobID, micros(s.cfg.IdempotencyTTL)).Scan(&keyJob)
		if errors.Is(err, pgx.ErrNoRows) {
			created = false
			return errReplay
		}
		return err
	})
	if errors.Is(err, errReplay) {
		job, ok, err := s.replay(ctx, nj.Owner, nj.IdempotencyKey, reqHash)
		if err == nil && !ok {
			// The live key vanished between statements (purged); let the client retry.
			err = fmt.Errorf("%w: idempotency key changed concurrently", store.ErrConflict)
		}
		return job, false, err
	}
	if err != nil {
		return store.Job{}, false, err
	}
	return job, created, nil
}

var errReplay = errors.New("idempotent replay")

// replay returns the job of a live idempotency key. ok=false when the key is
// absent or expired.
func (s *Store) replay(ctx context.Context, owner, key, reqHash string) (store.Job, bool, error) {
	var storedHash string
	row := s.pool.QueryRow(ctx, `
SELECT k.request_sha256, `+jobColumns+`
FROM idempotency_keys k JOIN resolution_jobs j ON j.owner_id = k.owner_id AND j.id = k.job_id
WHERE k.owner_id = $1 AND k.key = $2 AND k.expires_at > now()`, owner, key)
	var j store.Job
	var status string
	err := row.Scan(&storedHash, &j.ID, &j.Owner, &status, &j.Provider, &j.Model, &j.InputKind, &j.Options,
		&j.RunMetadata, &j.Errors, &j.InputSHA256, &j.ConfigSHA256, &j.Total, &j.Processed, &j.Attempts,
		&j.CreatedAt, &j.UpdatedAt, &j.FinishedAt, &j.ExpiresAt, &j.Deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Job{}, false, nil
	}
	if err != nil {
		return store.Job{}, false, mapErr(err)
	}
	if storedHash != reqHash {
		return store.Job{}, false, store.ErrIdempotencyConflict
	}
	j.Status = store.JobStatus(status)
	return j, true, nil
}

// GetJob returns a job owned by owner. Other owners' jobs are ErrNotFound.
func (s *Store) GetJob(ctx context.Context, owner, id string) (store.Job, error) {
	if !store.ValidUUID(id) {
		return store.Job{}, store.ErrNotFound
	}
	j, err := scanJob(s.pool.QueryRow(ctx, `SELECT `+jobColumns+` FROM resolution_jobs j WHERE j.owner_id = $1 AND j.id = $2 AND j.expires_at > now()`, owner, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return j, store.ErrNotFound
	}
	return j, mapErr(err)
}

// CancelJob applies a cancel request under the job row lock. queued jobs end
// immediately; running jobs become cancelling and the worker (or the reaper
// after lease expiry) finalizes them; other states are returned unchanged.
// The API returns 200 when the returned status is terminal, otherwise 202.
func (s *Store) CancelJob(ctx context.Context, owner, id string) (store.Job, error) {
	j, _, e := s.CancelJobWithOutcome(ctx, owner, id)
	return j, e
}

// CancelJobWithOutcome returns acceptance atomically with the state change.
func (s *Store) CancelJobWithOutcome(ctx context.Context, owner, id string) (store.Job, bool, error) {
	if !store.ValidUUID(id) {
		return store.Job{}, false, store.ErrNotFound
	}
	var job store.Job
	accepted := false
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM resolution_jobs WHERE owner_id = $1 AND id = $2 AND expires_at > now() FOR UPDATE`, owner, id).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		switch store.JobStatus(status) {
		case store.StatusCancelling:
			accepted = true
		case store.StatusQueued:
			accepted = true
			_, err = tx.Exec(ctx, `UPDATE resolution_jobs SET status = 'cancelled', finished_at = now(), updated_at = now() WHERE id = $1`, id)
		case store.StatusRunning:
			accepted = true
			_, err = tx.Exec(ctx, `UPDATE resolution_jobs SET status = 'cancelling', updated_at = now() WHERE id = $1`, id)
		}
		if err != nil {
			return err
		}
		job, err = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM resolution_jobs j WHERE j.id = $1`, id))
		return err
	})
	return job, accepted, err
}

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mskmemory/gocpe-ai/internal/store"
)

// AcquireJob claims one job with FOR UPDATE SKIP LOCKED: first a running job
// whose lease expired (crashed worker), then the oldest queued job. Jobs past
// their deadline or with attempts >= MaxAttempts are left to ReapExpired.
func (s *Store) AcquireJob(ctx context.Context, o store.AcquireOptions) (store.Lease, store.Job, error) {
	if o.LeaseDuration <= 0 || o.MaxAttempts < 1 {
		return store.Lease{}, store.Job{}, fmt.Errorf("%w: lease duration and max attempts must be positive", store.ErrInvalid)
	}
	token := store.NewID()
	var job store.Job
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `
SELECT id::text FROM resolution_jobs
WHERE status = 'running' AND lease_until <= now() AND deadline > now() AND attempts < $1
ORDER BY lease_until, id LIMIT 1 FOR UPDATE SKIP LOCKED`, o.MaxAttempts).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(ctx, `
SELECT id::text FROM resolution_jobs
WHERE status = 'queued' AND deadline > now() AND attempts < $1
ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED`, o.MaxAttempts).Scan(&id)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNoJob
		}
		if err != nil {
			return err
		}
		job, err = scanJob(tx.QueryRow(ctx, `
UPDATE resolution_jobs j SET status = 'running', lease_token = $2, lease_until = now() + $3 * interval '1 microsecond',
    attempts = attempts + 1, updated_at = now()
WHERE j.id = $1 RETURNING `+jobColumns, id, token, micros(o.LeaseDuration)))
		return err
	})
	if err != nil {
		return store.Lease{}, store.Job{}, err
	}
	return store.Lease{JobID: job.ID, Token: token}, job, nil
}

// lockLease locks the job row if the lease is still valid.
func lockLease(ctx context.Context, tx pgx.Tx, l store.Lease) (store.Job, error) {
	if !store.ValidUUID(l.JobID) || !store.ValidUUID(l.Token) {
		return store.Job{}, store.ErrLeaseLost
	}
	j, err := scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+` FROM resolution_jobs j
WHERE j.id = $1 AND j.lease_token = $2 AND j.lease_until > clock_timestamp() AND j.status IN ('running','cancelling')
FOR UPDATE`, l.JobID, l.Token))
	if errors.Is(err, pgx.ErrNoRows) {
		return j, store.ErrLeaseLost
	}
	if err != nil {
		return j, err
	}
	var valid bool
	err = tx.QueryRow(ctx, `SELECT lease_until > clock_timestamp() AND deadline > clock_timestamp() FROM resolution_jobs WHERE id=$1`, l.JobID).Scan(&valid)
	if err == nil && !valid {
		return j, store.ErrLeaseLost
	}
	return j, err
}

// Heartbeat extends a valid lease. It does not extend past the deadline
// check: the worker must stop when Job.Deadline has passed.
func (s *Store) Heartbeat(ctx context.Context, l store.Lease, d time.Duration) (store.Job, error) {
	if d <= 0 {
		return store.Job{}, fmt.Errorf("%w: lease duration must be positive", store.ErrInvalid)
	}
	var job store.Job
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := lockLease(ctx, tx, l); err != nil {
			return err
		}
		var err error
		job, err = scanJob(tx.QueryRow(ctx, `UPDATE resolution_jobs j SET lease_until = now() + $2 * interval '1 microsecond', updated_at = now()
WHERE j.id = $1 RETURNING `+jobColumns, l.JobID, micros(d)))
		return err
	})
	return job, err
}

const componentColumns = `c.job_id::text, c.component_id, c.ordinal, c.source_pointer, c.normalized_input, c.raw_values, c.state, c.errors`

func scanComponent(row pgx.Row) (store.Component, error) {
	var c store.Component
	err := row.Scan(&c.JobID, &c.ID, &c.Ordinal, &c.SourcePointer, &c.Input, &c.Raw, &c.State, &c.Errors)
	return c, err
}

// NextComponents marks up to limit unfinished components running.
func (s *Store) NextComponents(ctx context.Context, l store.Lease, limit int) ([]store.Component, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: limit must be 1..1000", store.ErrInvalid)
	}
	var out []store.Component
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if j, err := lockLease(ctx, tx, l); err != nil {
			return err
		} else if j.Status != store.StatusRunning {
			return store.ErrLeaseLost
		}
		rows, err := tx.Query(ctx, `
UPDATE resolution_components c SET state = 'running'
WHERE c.job_id = $1 AND c.component_id IN (
    SELECT component_id FROM resolution_components
    WHERE job_id = $1 AND state <> 'done' ORDER BY ordinal LIMIT $2)
RETURNING `+componentColumns, l.JobID, limit)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.Component, error) { return scanComponent(r) })
		if err != nil {
			return err
		}
		sortComponents(out)
		return nil
	})
	return out, err
}

func sortComponents(cs []store.Component) {
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && cs[j].Ordinal < cs[j-1].Ordinal; j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
}

// AddUsage adds provider usage to run_metadata.usage under a valid lease.
func (s *Store) AddUsage(ctx context.Context, l store.Lease, u store.Usage) error {
	if u.InputTokens < 0 || u.OutputTokens < 0 || u.Calls < 0 {
		return fmt.Errorf("%w: usage must be non-negative", store.ErrInvalid)
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := lockLease(ctx, tx, l); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
UPDATE resolution_jobs SET updated_at = now(), run_metadata = jsonb_set(run_metadata, '{usage}', jsonb_build_object(
    'input_tokens',  COALESCE((run_metadata #>> '{usage,input_tokens}')::bigint, 0) + $2,
    'output_tokens', COALESCE((run_metadata #>> '{usage,output_tokens}')::bigint, 0) + $3,
    'calls',         COALESCE((run_metadata #>> '{usage,calls}')::bigint, 0) + $4), true)
WHERE id = $1`, l.JobID, u.InputTokens, u.OutputTokens, u.Calls)
		return err
	})
}

// FinishJob ends the job under a valid lease. completed requires every
// component to be done. A cancelling job always ends as cancelled.
func (s *Store) FinishJob(ctx context.Context, l store.Lease, status store.JobStatus, errs []store.ErrorEntry) (store.Job, error) {
	switch status {
	case store.StatusCompleted, store.StatusPartial, store.StatusFailed:
	default:
		return store.Job{}, fmt.Errorf("%w: worker can finish only as completed, partial or failed", store.ErrInvalid)
	}
	var job store.Job
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		cur, err := lockLease(ctx, tx, l)
		if err != nil {
			return err
		}
		final := status
		if cur.Status == store.StatusCancelling {
			final = store.StatusCancelled
		} else if status == store.StatusCompleted && cur.Processed != cur.Total {
			return fmt.Errorf("%w: completed requires all components done (%d/%d)", store.ErrConflict, cur.Processed, cur.Total)
		}
		job, err = scanJob(tx.QueryRow(ctx, `
UPDATE resolution_jobs j SET status = $2, finished_at = now(), updated_at = now(), lease_token = NULL, lease_until = NULL,
    errors = j.errors || $3::jsonb
WHERE j.id = $1 RETURNING `+jobColumns, l.JobID, string(final), string(mustJSON(emptySlice(errs)))))
		return err
	})
	return job, err
}

// ReapExpired finalizes abandoned or overdue jobs:
//   - cancelling with expired lease, or past deadline  -> cancelled
//   - running past deadline, or with expired lease and attempts >= maxAttempts
//     -> partial when at least one component is done, else failed
//   - queued past deadline -> failed
//
// Finalization clears the lease, so a late worker gets ErrLeaseLost.
func (s *Store) ReapExpired(ctx context.Context, maxAttempts int) (store.ReapResult, error) {
	if maxAttempts < 1 {
		return store.ReapResult{}, fmt.Errorf("%w: max attempts must be positive", store.ErrInvalid)
	}
	deadlineErr := string(mustJSON([]store.ErrorEntry{{Code: "DEADLINE_EXCEEDED", Message: "job exceeded its execution deadline"}}))
	attemptsErr := string(mustJSON([]store.ErrorEntry{{Code: "ATTEMPTS_EXHAUSTED", Message: "worker lease expired too many times"}}))
	var res store.ReapResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
UPDATE resolution_jobs SET status = 'cancelled', finished_at = now(), updated_at = now(), lease_token = NULL, lease_until = NULL
WHERE status = 'cancelling' AND (lease_until <= now() OR deadline <= now())`)
		if err != nil {
			return err
		}
		res.Cancelled = tag.RowsAffected()
		rows, err := tx.Query(ctx, `
UPDATE resolution_jobs SET
    status = CASE WHEN status = 'running' AND processed > 0 THEN 'partial' ELSE 'failed' END,
    finished_at = now(), updated_at = now(), lease_token = NULL, lease_until = NULL,
    errors = errors || CASE WHEN deadline <= now() THEN $2::jsonb ELSE $3::jsonb END
WHERE (status IN ('queued','running') AND deadline <= now())
   OR (status = 'running' AND lease_until <= now() AND attempts >= $1)
RETURNING status`, maxAttempts, deadlineErr, attemptsErr)
		if err != nil {
			return err
		}
		statuses, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, st := range statuses {
			if st == string(store.StatusPartial) {
				res.Partial++
			} else {
				res.Failed++
			}
		}
		return nil
	})
	return res, err
}

// PurgeExpired deletes up to batch expired idempotency keys and terminal jobs
// past retention. Call repeatedly until both counts are zero.
func (s *Store) PurgeExpired(ctx context.Context, batch int) (store.PurgeResult, error) {
	if batch < 1 {
		return store.PurgeResult{}, fmt.Errorf("%w: batch must be positive", store.ErrInvalid)
	}
	var res store.PurgeResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM idempotency_keys WHERE (owner_id, key) IN (
    SELECT owner_id, key FROM idempotency_keys WHERE expires_at <= now() LIMIT $1)`, batch)
		if err != nil {
			return err
		}
		res.IdempotencyKeys = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `DELETE FROM resolution_jobs WHERE id IN (
    SELECT id FROM resolution_jobs WHERE expires_at <= now()
      AND status IN ('completed','partial','failed','cancelled') LIMIT $1)`, batch)
		if err != nil {
			return err
		}
		res.Jobs = tag.RowsAffected()
		return nil
	})
	return res, err
}

// errorsJSON encodes component errors as a JSON array.
func errorsJSON(errs []store.ErrorEntry) (string, error) {
	for _, e := range errs {
		if e.Code == "" {
			return "", fmt.Errorf("%w: error code is required", store.ErrInvalid)
		}
	}
	b, err := json.Marshal(emptySlice(errs))
	return string(b), err
}

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

var _ store.SyncStore = (*Store)(nil)

func (s *Store) AcquireSync(ctx context.Context, source, stream string, d time.Duration) (store.SyncLease, error) {
	l := store.SyncLease{Source: source, Stream: stream, Token: store.NewID()}
	if !oneOf(source, "nvd", "osv") || stream == "" || d <= 0 {
		return l, store.ErrInvalid
	}
	err := s.pool.QueryRow(ctx, `INSERT INTO source_sync_state(source,stream,status,lease_token,lease_until,updated_at,cursor) VALUES($1,$2,'running',$3,clock_timestamp()+$4*interval '1 second',clock_timestamp(),'{}') ON CONFLICT(source,stream) DO UPDATE SET status='running',lease_token=EXCLUDED.lease_token,lease_until=EXCLUDED.lease_until,updated_at=clock_timestamp() WHERE source_sync_state.lease_until IS NULL OR source_sync_state.lease_until<=clock_timestamp() RETURNING coalesce(cursor,'{}'),watermark`, source, stream, l.Token, d.Seconds()).Scan(&l.Cursor, &l.Watermark)
	if errors.Is(err, pgx.ErrNoRows) {
		err = store.ErrConflict
	}
	return l, mapErr(err)
}
func (s *Store) CheckpointSync(ctx context.Context, l store.SyncLease, cursor json.RawMessage, d time.Duration) error {
	if !isObject(cursor) || d <= 0 {
		return store.ErrInvalid
	}
	tag, e := s.pool.Exec(ctx, `UPDATE source_sync_state SET cursor=$4,lease_until=clock_timestamp()+$5*interval '1 second',updated_at=clock_timestamp() WHERE source=$1 AND stream=$2 AND lease_token=$3 AND lease_until>clock_timestamp()`, l.Source, l.Stream, l.Token, cursor, d.Seconds())
	if e != nil {
		return mapErr(e)
	}
	if tag.RowsAffected() != 1 {
		return store.ErrLeaseLost
	}
	return nil
}
func (s *Store) FinishSync(ctx context.Context, l store.SyncLease, watermark *time.Time, complete bool) error {
	status := "failed"
	if complete {
		status = "idle"
	}
	tag, e := s.pool.Exec(ctx, `UPDATE source_sync_state SET status=$4,watermark=CASE WHEN $5 THEN $6 ELSE watermark END,cursor=CASE WHEN $5 THEN '{}'::jsonb ELSE cursor END,lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE source=$1 AND stream=$2 AND lease_token=$3 AND lease_until>clock_timestamp()`, l.Source, l.Stream, l.Token, status, complete, watermark)
	if e != nil {
		return mapErr(e)
	}
	if tag.RowsAffected() != 1 {
		return store.ErrLeaseLost
	}
	return nil
}
func (s *Store) UpsertSourceRecord(ctx context.Context, r store.SourceRecord) error {
	if err := validateSourceRecord(r); err != nil {
		return err
	}
	_, e := s.pool.Exec(ctx, `INSERT INTO source_records(source,stream,record_id,modified_at,fetched_at,raw_record) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(source,stream,record_id) DO UPDATE SET modified_at=EXCLUDED.modified_at,fetched_at=EXCLUDED.fetched_at,raw_record=EXCLUDED.raw_record WHERE source_records.modified_at<=EXCLUDED.modified_at`, r.Source, r.Stream, r.ID, r.ModifiedAt, r.FetchedAt, r.Raw)
	return mapErr(e)
}

// UpsertSourceRecordBatch commits a bounded source-record batch in one
// transaction, so full NVD ingestion does not fsync every record separately.
func (s *Store) UpsertSourceRecordBatch(ctx context.Context, records []store.SourceRecord) error {
	if len(records) > 1000 {
		return fmt.Errorf("%w: source record batch exceeds 1000 records", store.ErrInvalid)
	}
	for _, r := range records {
		if err := validateSourceRecord(r); err != nil {
			return err
		}
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, r := range records {
			if _, err := tx.Exec(ctx, `INSERT INTO source_records(source,stream,record_id,modified_at,fetched_at,raw_record) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(source,stream,record_id) DO UPDATE SET modified_at=EXCLUDED.modified_at,fetched_at=EXCLUDED.fetched_at,raw_record=EXCLUDED.raw_record WHERE source_records.modified_at<=EXCLUDED.modified_at`, r.Source, r.Stream, r.ID, r.ModifiedAt, r.FetchedAt, r.Raw); err != nil {
				return err
			}
		}
		return nil
	})
}

func validateSourceRecord(r store.SourceRecord) error {
	if r.Source != "nvd" || !oneOf(r.Stream, "cve", "match", "history", "source") || r.ID == "" || r.ModifiedAt.IsZero() || r.FetchedAt.IsZero() || !isObject(r.Raw) {
		return store.ErrInvalid
	}
	return nil
}
func (s *Store) GetSourceRecord(ctx context.Context, source, stream, id string) (store.SourceRecord, error) {
	r := store.SourceRecord{Source: source, Stream: stream, ID: id}
	e := s.pool.QueryRow(ctx, `SELECT modified_at,fetched_at,raw_record FROM source_records WHERE source=$1 AND stream=$2 AND record_id=$3`, source, stream, id).Scan(&r.ModifiedAt, &r.FetchedAt, &r.Raw)
	if errors.Is(e, pgx.ErrNoRows) {
		e = store.ErrNotFound
	}
	return r, mapErr(e)
}

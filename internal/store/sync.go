package store

import (
	"context"
	"encoding/json"
	"time"
)

// SourceRecord preserves an entire non-dictionary source record, without
// conflating CVE match criteria with registered CPE names.
type SourceRecord struct {
	Source, Stream, ID    string
	ModifiedAt, FetchedAt time.Time
	Raw                   json.RawMessage
}
type SyncLease struct {
	Source, Stream, Token string
	Cursor                json.RawMessage
	Watermark             *time.Time
}

// SyncStore leases one stream. Checkpoints advance only after all records in
// the corresponding page have been committed. Retries replay idempotent upserts.
type SyncStore interface {
	AcquireSync(context.Context, string, string, time.Duration) (SyncLease, error)
	CheckpointSync(context.Context, SyncLease, json.RawMessage, time.Duration) error
	FinishSync(context.Context, SyncLease, *time.Time, bool) error
	UpsertSourceRecord(context.Context, SourceRecord) error
	GetSourceRecord(context.Context, string, string, string) (SourceRecord, error)
}

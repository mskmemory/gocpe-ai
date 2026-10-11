// Package postgres implements internal/store contracts on PostgreSQL (pgx).
//
// All time comparisons use the database clock (now()) so API servers and
// workers with skewed clocks agree on lease and expiry decisions. Network I/O
// never happens while a transaction is open: callers fetch external data
// first, then write it in short transactions.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mskmemory/gocpe-ai/internal/store"
)

// Config holds retention and execution limits. Zero values use defaults
// from docs/database-design.md.
type Config struct {
	Retention        time.Duration // job/result/evidence retention (default 30 days)
	IdempotencyTTL   time.Duration // idempotency key lifetime (default 24 hours)
	ExecutionTimeout time.Duration // job deadline after creation (default 1 hour)
}

func (c Config) withDefaults() Config {
	if c.Retention <= 0 {
		c.Retention = 30 * 24 * time.Hour
	}
	if c.IdempotencyTTL <= 0 {
		c.IdempotencyTTL = 24 * time.Hour
	}
	if c.ExecutionTimeout <= 0 {
		c.ExecutionTimeout = time.Hour
	}
	return c
}

// Store implements store.Dictionary, store.Jobs and store.Queue.
type Store struct {
	pool *pgxpool.Pool
	cfg  Config
}

var (
	_ store.Dictionary = (*Store)(nil)
	_ store.Jobs       = (*Store)(nil)
	_ store.Queue      = (*Store)(nil)
)

// New wraps an existing pool. The caller owns the pool.
func New(pool *pgxpool.Pool, cfg Config) *Store {
	return &Store{pool: pool, cfg: cfg.withDefaults()}
}

// OpenPool creates a pool with a bounded connect timeout and UTC session
// time zone, and verifies connectivity. Request deadlines come from ctx.
func OpenPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// Do not echo the DSN: it may contain a password.
		return nil, errors.New("postgres: invalid database URL")
	}
	if pc.ConnConfig.ConnectTimeout == 0 || pc.ConnConfig.ConnectTimeout > 10*time.Second {
		pc.ConnConfig.ConnectTimeout = 5 * time.Second
	}
	pc.ConnConfig.RuntimeParams["timezone"] = "UTC"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// inTx runs f in a transaction. The rollback uses a fresh short context so a
// cancelled request still releases its locks promptly.
func (s *Store) inTx(ctx context.Context, f func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rctx)
	}()
	if err := f(tx); err != nil {
		return mapErr(err)
	}
	return mapErr(tx.Commit(ctx))
}

// mapErr converts constraint violations to store sentinels without leaking
// values (constraint names only).
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: unique constraint %s", store.ErrConflict, pe.ConstraintName)
		case "23503", "23514", "23502", "22P02", "23P01": // fk, check, not null, invalid text, exclusion
			return fmt.Errorf("%w: constraint %s (%s)", store.ErrInvalid, pe.ConstraintName, pe.Code)
		}
	}
	return err
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// canonicalJSON re-encodes a single JSON value with sorted object keys and
// preserved array order. Numbers keep their literal text (json.Number).
func canonicalJSON(b []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: malformed JSON", store.ErrInvalid)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after JSON value", store.ErrInvalid)
	}
	return json.Marshal(v)
}

func isObject(b []byte) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(b, &m) == nil && m != nil
}

func objectOrEmpty(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return []byte("{}"), nil
	}
	if !isObject(b) {
		return nil, fmt.Errorf("%w: expected JSON object", store.ErrInvalid)
	}
	return b, nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only called with plain data types
	}
	return b
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func pageLimit(n int) (int, error) {
	if n == 0 {
		return 100, nil
	}
	if n < 1 || n > 200 {
		return 0, fmt.Errorf("%w: limit must be 1..200", store.ErrInvalid)
	}
	return n, nil
}

// micros encodes a duration for `$n * interval '1 microsecond'`.
func micros(d time.Duration) int64 { return d.Microseconds() }

func requireUUID(id string) error {
	if !store.ValidUUID(id) {
		return fmt.Errorf("%w: malformed UUID", store.ErrInvalid)
	}
	return nil
}

func emptySlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

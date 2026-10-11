// Package db embeds the numbered PostgreSQL migrations and applies them.
//
// Files are named NNNNNN_description.up.sql / NNNNNN_description.down.sql.
// Each migration runs in its own transaction and is recorded in
// schema_migrations together with the SHA-256 of its up script, so an edited
// migration that was already applied is detected instead of silently ignored.
// Concurrent runners are serialized with a session advisory lock.
package db

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// advisoryLockKey is an arbitrary constant shared by all migration runners.
const advisoryLockKey int64 = 727311001

var fileName = regexp.MustCompile(`^(\d{6})_([a-z0-9_]+)\.(up|down)\.sql$`)

// ErrHistoryMismatch means the database records a migration that differs from
// (or is unknown to) this binary. Never "fix" this by editing schema_migrations.
var ErrHistoryMismatch = errors.New("db: migration history mismatch")

// Migration is one numbered migration.
type Migration struct {
	Version  int64
	Name     string
	Up       string
	Down     string
	Checksum string // hex SHA-256 of Up
}

// AppliedMigration is a row of schema_migrations.
type AppliedMigration struct {
	Version   int64
	Name      string
	Checksum  string
	AppliedAt time.Time
}

// Migrations returns the embedded migrations sorted by version.
func Migrations() ([]Migration, error) {
	return load(migrationFiles)
}

func load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, err
	}
	byVersion := map[int64]*Migration{}
	for _, e := range entries {
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("db: unexpected migration file name %q", e.Name())
		}
		v, _ := strconv.ParseInt(m[1], 10, 64)
		b, err := fs.ReadFile(fsys, "migrations/"+e.Name())
		if err != nil {
			return nil, err
		}
		mig := byVersion[v]
		if mig == nil {
			mig = &Migration{Version: v, Name: m[2]}
			byVersion[v] = mig
		} else if mig.Name != m[2] {
			return nil, fmt.Errorf("db: migration %06d has inconsistent names", v)
		}
		if m[3] == "up" {
			mig.Up = string(b)
			sum := sha256.Sum256(b)
			mig.Checksum = hex.EncodeToString(sum[:])
		} else {
			mig.Down = string(b)
		}
	}
	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.Up == "" || m.Down == "" {
			return nil, fmt.Errorf("db: migration %06d needs both up and down files", m.Version)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != int64(i+1) {
			return nil, fmt.Errorf("db: migration versions must be contiguous from 000001; found %06d", m.Version)
		}
	}
	return out, nil
}

// Migrate applies all pending migrations. It is safe to call concurrently
// and on every start-up.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	migs, err := Migrations()
	if err != nil {
		return err
	}
	return withLock(ctx, pool, func(conn *pgx.Conn) error {
		applied, err := verifiedHistory(ctx, conn, migs)
		if err != nil {
			return err
		}
		for _, m := range migs[len(applied):] {
			if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, m.Up); err != nil {
					return fmt.Errorf("db: apply %06d_%s: %w", m.Version, m.Name, err)
				}
				_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version, name, checksum) VALUES ($1, $2, $3)`,
					m.Version, m.Name, m.Checksum)
				return err
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Rollback reverts the latest `steps` applied migrations. DESTRUCTIVE: down
// scripts drop tables and data. For explicit operator use only.
func Rollback(ctx context.Context, pool *pgxpool.Pool, steps int) error {
	if steps < 1 {
		return fmt.Errorf("db: rollback steps must be >= 1")
	}
	migs, err := Migrations()
	if err != nil {
		return err
	}
	return withLock(ctx, pool, func(conn *pgx.Conn) error {
		applied, err := verifiedHistory(ctx, conn, migs)
		if err != nil {
			return err
		}
		if steps > len(applied) {
			return fmt.Errorf("db: cannot roll back %d migrations; %d applied", steps, len(applied))
		}
		for i := len(applied) - 1; i >= len(applied)-steps; i-- {
			m := migs[i]
			if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, m.Down); err != nil {
					return fmt.Errorf("db: revert %06d_%s: %w", m.Version, m.Name, err)
				}
				_, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, m.Version)
				return err
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Status returns the applied migrations and the number pending.
func Status(ctx context.Context, pool *pgxpool.Pool) (applied []AppliedMigration, pending int, err error) {
	migs, err := Migrations()
	if err != nil {
		return nil, 0, err
	}
	err = withLock(ctx, pool, func(conn *pgx.Conn) error {
		applied, err = verifiedHistory(ctx, conn, migs)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return applied, len(migs) - len(applied), nil
}

func withLock(ctx context.Context, pool *pgxpool.Pool, f func(*pgx.Conn) error) error {
	c, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer c.Release()
	conn := c.Conn()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return err
	}
	defer func() {
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, advisoryLockKey); err != nil {
			// Closing the session releases the lock; do not return a pooled
			// connection that may still hold it.
			_ = conn.Close(uctx)
		}
	}()
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version bigint PRIMARY KEY,
		name text NOT NULL,
		checksum text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	return f(conn)
}

// verifiedHistory requires the applied set to be a checksum-identical prefix
// of the embedded migrations.
func verifiedHistory(ctx context.Context, conn *pgx.Conn, migs []Migration) ([]AppliedMigration, error) {
	rows, err := conn.Query(ctx, `SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	applied, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (AppliedMigration, error) {
		var a AppliedMigration
		err := r.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt)
		return a, err
	})
	if err != nil {
		return nil, err
	}
	if len(applied) > len(migs) {
		return nil, fmt.Errorf("%w: database has %d migrations, binary knows %d", ErrHistoryMismatch, len(applied), len(migs))
	}
	for i, a := range applied {
		m := migs[i]
		if a.Version != m.Version || a.Checksum != m.Checksum {
			return nil, fmt.Errorf("%w: version %06d differs from embedded migration", ErrHistoryMismatch, a.Version)
		}
	}
	return applied, nil
}

package syncdata

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/mskmemory/gocpe-ai/internal/lookup"
	"github.com/mskmemory/gocpe-ai/internal/osv"
	"io"
	"os"
	"strings"
	"time"
)

const OSVArchiveURL = "https://storage.googleapis.com/osv-vulnerabilities/all.zip"

type OSVConfig struct {
	Archive        string
	MaxRecords     int
	MaxRecordBytes int64
}
type zipCursor struct {
	SHA256  string    `json:"sha256"`
	Index   int       `json:"index"`
	Started time.Time `json:"started"`
}

// OSV ingests the official global all.zip, including withdrawn and unsupported
// ecosystems. It never extracts archive paths to disk. Resume is tied to content
// hash, so a replaced archive cannot accidentally skip records.
func OSV(ctx context.Context, repo Repository, c OSVConfig) (err error) {
	if c.MaxRecordBytes <= 0 {
		c.MaxRecordBytes = 32 << 20
	}
	f, e := os.Open(c.Archive)
	if e != nil {
		return e
	}
	defer f.Close()
	hash := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, re := f.Read(buf)
		hash.Write(buf[:n])
		if re == io.EOF {
			break
		}
		if re != nil {
			return re
		}
	}
	stat, e := f.Stat()
	if e != nil {
		return e
	}
	archive, e := zip.NewReader(f, stat.Size())
	if e != nil {
		return e
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	lease, e := repo.AcquireSync(ctx, "osv", "all", 5*time.Minute)
	if e != nil {
		return e
	}
	complete := false
	var watermark *time.Time
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		err = errors.Join(err, repo.FinishSync(cleanup, lease, watermark, complete))
	}()
	cursor := zipCursor{SHA256: digest, Started: time.Now().UTC()}
	if len(lease.Cursor) > 2 {
		var prior zipCursor
		if json.Unmarshal(lease.Cursor, &prior) != nil {
			return lookup.ErrProtocol
		}
		if prior.SHA256 == digest {
			cursor = prior
		}
	}
	processed := 0
	for i := cursor.Index; i < len(archive.File); i++ {
		if e = ctx.Err(); e != nil {
			return e
		}
		entry := archive.File[i]
		if entry.FileInfo().IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name, ".json") {
			return errors.New("sync: unexpected archive member")
		}
		if c.MaxRecords > 0 && processed >= c.MaxRecords {
			return lookup.ErrPageLimit
		}
		if entry.UncompressedSize64 > uint64(c.MaxRecordBytes) {
			return errors.New("sync: record size limit")
		}
		reader, e := entry.Open()
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(reader, c.MaxRecordBytes+1))
		reader.Close()
		if e != nil {
			return e
		}
		if int64(len(raw)) > c.MaxRecordBytes {
			return errors.New("sync: record size limit")
		}
		rec, e := osv.DecodeRecord(raw, time.Now().UTC())
		if e != nil {
			return e
		}
		if _, e = repo.UpsertOSV(ctx, rec); e != nil {
			return e
		}
		cursor.Index = i + 1
		processed++
		b, _ := json.Marshal(cursor)
		if e = repo.CheckpointSync(ctx, lease, b, 5*time.Minute); e != nil {
			return e
		}
	}
	complete = true
	watermark = &cursor.Started
	return nil
}

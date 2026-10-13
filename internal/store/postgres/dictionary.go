package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mskmemory/gocpe-ai/internal/store"
)

// UpsertCPE inserts or updates an NVD CPE. A record older than the stored
// source_modified_at is not applied (Applied=false). The deprecated flag and
// replacement list are replaced in the same transaction.
func (s *Store) UpsertCPE(ctx context.Context, rec store.CPERecord) (store.UpsertResult, error) {
	var res store.UpsertResult
	err := s.inTx(ctx, func(tx pgx.Tx) error { var e error; res, e = upsertCPE(ctx, tx, rec); return e })
	return res, err
}

// UpsertCPEBatch commits a bounded page chunk atomically, avoiding one fsync
// per dictionary record during full NVD ingestion.
func (s *Store) UpsertCPEBatch(ctx context.Context, records []store.CPERecord) error {
	if len(records) == 0 {
		return nil
	}
	if len(records) > 1000 {
		return fmt.Errorf("%w: CPE batch exceeds 1000 records", store.ErrInvalid)
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, rec := range records {
			if _, err := upsertCPE(ctx, tx, rec); err != nil {
				return err
			}
		}
		return nil
	})
}

func upsertCPE(ctx context.Context, tx pgx.Tx, rec store.CPERecord) (store.UpsertResult, error) {
	if err := requireUUID(rec.NameID); err != nil {
		return store.UpsertResult{}, err
	}
	if rec.SourceModifiedAt.IsZero() || rec.FetchedAt.IsZero() {
		return store.UpsertResult{}, fmt.Errorf("%w: source_modified_at and fetched_at are required", store.ErrInvalid)
	}
	if !isObject(rec.Raw) {
		return store.UpsertResult{}, fmt.Errorf("%w: raw NVD record must be a JSON object", store.ErrInvalid)
	}
	p, err := parseCPE(rec.Name)
	if err != nil {
		return store.UpsertResult{}, err
	}
	replacements, err := uniqueUUIDs(rec.ReplacedBy, rec.NameID)
	if err != nil {
		return store.UpsertResult{}, err
	}
	hash := sha256Hex([]byte(rec.Name))
	var res store.UpsertResult
	var existingName string
	err = tx.QueryRow(ctx, `SELECT cpe_name FROM nvd_cpes WHERE cpe_sha256 = $1`, hash).Scan(&existingName)
	if err == nil && existingName != rec.Name {
		return res, store.ErrHashCollision
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return res, err
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO nvd_cpes (cpe_name_id, cpe_name, cpe_sha256, part, vendor, product, version,
                      attributes, titles, deprecated, source_modified_at, fetched_at, raw_record)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11, $12, $13::jsonb)
ON CONFLICT (cpe_name_id) DO UPDATE SET
    cpe_name = EXCLUDED.cpe_name, cpe_sha256 = EXCLUDED.cpe_sha256, part = EXCLUDED.part,
    vendor = EXCLUDED.vendor, product = EXCLUDED.product, version = EXCLUDED.version,
    attributes = EXCLUDED.attributes, titles = EXCLUDED.titles, deprecated = EXCLUDED.deprecated,
    source_modified_at = EXCLUDED.source_modified_at, fetched_at = EXCLUDED.fetched_at,
    raw_record = EXCLUDED.raw_record
WHERE nvd_cpes.source_modified_at <= EXCLUDED.source_modified_at`,
		rec.NameID, rec.Name, hash, p.part, p.vendor, p.product, p.version, string(mustJSON(p.attributes)), string(mustJSON(emptySlice(rec.Titles))), rec.Deprecated, rec.SourceModifiedAt.UTC(), rec.FetchedAt.UTC(), string(rec.Raw))
	if err != nil {
		return res, err
	}
	if tag.RowsAffected() == 0 {
		return res, nil
	}
	res.Applied = true
	if _, err = tx.Exec(ctx, `DELETE FROM nvd_cpe_replacements WHERE cpe_name_id = $1`, rec.NameID); err != nil {
		return res, err
	}
	for _, r := range replacements {
		if _, err = tx.Exec(ctx, `INSERT INTO nvd_cpe_replacements (cpe_name_id, replacement_cpe_name_id) VALUES ($1, $2)`, rec.NameID, r); err != nil {
			return res, err
		}
	}
	return res, nil
}

func uniqueUUIDs(ids []string, self string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if err := requireUUID(id); err != nil {
			return nil, err
		}
		id = strings.ToLower(id)
		if strings.EqualFold(id, self) {
			return nil, fmt.Errorf("%w: CPE cannot replace itself", store.ErrInvalid)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

const cpeColumns = `c.cpe_name_id::text, c.cpe_name, c.part, c.vendor, c.product, c.version,
    c.attributes, c.titles, c.deprecated, c.source_modified_at, c.fetched_at,
    COALESCE((SELECT array_agg(r.replacement_cpe_name_id::text ORDER BY r.replacement_cpe_name_id)
              FROM nvd_cpe_replacements r WHERE r.cpe_name_id = c.cpe_name_id), '{}')`

func scanCPE(row pgx.Row, withRaw bool) (store.CPERecord, error) {
	var c store.CPERecord
	var attrs, titles []byte
	dest := []any{&c.NameID, &c.Name, &c.Part, &c.Vendor, &c.Product, &c.Version,
		&attrs, &titles, &c.Deprecated, &c.SourceModifiedAt, &c.FetchedAt, &c.ReplacedBy}
	if withRaw {
		dest = append(dest, &c.Raw)
	}
	if err := row.Scan(dest...); err != nil {
		return c, err
	}
	if err := json.Unmarshal(attrs, &c.Attributes); err != nil {
		return c, err
	}
	if err := json.Unmarshal(titles, &c.Titles); err != nil {
		return c, err
	}
	return c, nil
}

// GetCPE returns one CPE including its raw NVD record.
func (s *Store) GetCPE(ctx context.Context, nameID string) (store.CPERecord, error) {
	if !store.ValidUUID(nameID) {
		return store.CPERecord{}, store.ErrNotFound
	}
	c, err := scanCPE(s.pool.QueryRow(ctx, `SELECT `+cpeColumns+`, c.raw_record FROM nvd_cpes c WHERE c.cpe_name_id = $1`, nameID), true)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, store.ErrNotFound
	}
	return c, mapErr(err)
}

// SearchCPEs pages the local CPE dictionary by cpe_name_id. Raw records are
// not included.
func (s *Store) SearchCPEs(ctx context.Context, q store.CPEQuery) (store.CPEPage, error) {
	limit, err := pageLimit(q.Limit)
	if err != nil {
		return store.CPEPage{}, err
	}
	if q.After != "" {
		if err := requireUUID(q.After); err != nil {
			return store.CPEPage{}, err
		}
	}
	rows, err := s.pool.Query(ctx, `SELECT `+cpeColumns+` FROM nvd_cpes c
WHERE ($1 = '' OR c.vendor = $1)
  AND ($2 = '' OR c.product = $2)
  AND ($3::boolean IS NULL OR c.deprecated = $3)
  AND ($4 = '' OR c.cpe_name ILIKE $4 ESCAPE '\'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(c.titles) t(v) WHERE t.v ILIKE $4 ESCAPE '\'))
  AND ($5::uuid IS NULL OR c.cpe_name_id > $5::uuid)
ORDER BY c.cpe_name_id
LIMIT $6`, q.Vendor, q.Product, q.Deprecated, likePattern(q.Query), nullIfEmpty(q.After), limit+1)
	if err != nil {
		return store.CPEPage{}, mapErr(err)
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.CPERecord, error) { return scanCPE(r, false) })
	if err != nil {
		return store.CPEPage{}, mapErr(err)
	}
	page := store.CPEPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextAfter = items[limit-1].NameID
	}
	return page, nil
}

// likePattern builds a substring pattern with LIKE metacharacters escaped.
// An empty query yields "" (no filter).
func likePattern(q string) string {
	if q == "" {
		return ""
	}
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(q) + "%"
}

// EnsurePURL canonicalizes and stores a PURL.
func (s *Store) EnsurePURL(ctx context.Context, raw string) (store.PURL, error) {
	var out store.PURL
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = ensurePURL(ctx, tx, raw)
		return err
	})
	return out, err
}

func ensurePURL(ctx context.Context, tx pgx.Tx, raw string) (store.PURL, error) {
	p, err := canonicalPURL(raw)
	if err != nil {
		return store.PURL{}, err
	}
	hash := sha256Hex([]byte(p.canonical))
	if _, err := tx.Exec(ctx, `
INSERT INTO purls (id, canonical_purl, purl_sha256, normalization_version, type, namespace, name, version, qualifiers, subpath)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
ON CONFLICT (purl_sha256) DO NOTHING`,
		store.NewID(), p.canonical, hash, purlNormalizationVersion, p.purl.Type,
		nullIfEmpty(p.purl.Namespace), p.purl.Name, nullIfEmpty(p.purl.Version),
		string(mustJSON(p.qualifiers)), nullIfEmpty(p.purl.Subpath)); err != nil {
		return store.PURL{}, err
	}
	row := tx.QueryRow(ctx, `SELECT `+purlColumns+` FROM purls p WHERE p.purl_sha256 = $1`, hash)
	got, err := scanPURL(row, false)
	if err != nil {
		return store.PURL{}, err
	}
	if got.Canonical != p.canonical {
		return store.PURL{}, store.ErrHashCollision
	}
	return got, nil
}

const purlColumns = `p.id::text, p.canonical_purl, p.normalization_version, p.type,
    COALESCE(p.namespace, ''), p.name, COALESCE(p.version, ''), p.qualifiers, COALESCE(p.subpath, '')`

func scanPURL(row pgx.Row, withOSV bool) (store.PURL, error) {
	var p store.PURL
	var quals []byte
	dest := []any{&p.ID, &p.Canonical, &p.NormalizationVersion, &p.Type, &p.Namespace, &p.Name, &p.Version, &quals, &p.Subpath}
	if withOSV {
		dest = append(dest, &p.OSVRecordIDs, &p.ObservedAt)
	}
	if err := row.Scan(dest...); err != nil {
		return p, err
	}
	return p, json.Unmarshal(quals, &p.Qualifiers)
}

// SearchPURLs returns PURLs linked to at least one non-withdrawn OSV record,
// aggregated to one row per PURL.
func (s *Store) SearchPURLs(ctx context.Context, q store.PURLQuery) (store.PURLPage, error) {
	limit, err := pageLimit(q.Limit)
	if err != nil {
		return store.PURLPage{}, err
	}
	if q.After != "" {
		if err := requireUUID(q.After); err != nil {
			return store.PURLPage{}, err
		}
	}
	rows, err := s.pool.Query(ctx, `SELECT `+purlColumns+`, agg.ids, agg.observed
FROM purls p
JOIN LATERAL (
    SELECT array_agg(DISTINCT r.osv_id ORDER BY r.osv_id) AS ids, max(r.fetched_at) AS observed
    FROM osv_affected_packages a JOIN osv_records r ON r.osv_id = a.osv_id
    WHERE a.purl_id = p.id AND r.withdrawn_at IS NULL
) agg ON agg.ids IS NOT NULL
WHERE ($1 = '' OR p.type = $1)
  AND ($2 = '' OR p.namespace = $2)
  AND ($3 = '' OR p.name = $3)
  AND ($4 = '' OR p.canonical_purl ILIKE $4 ESCAPE '\')
  AND ($5::uuid IS NULL OR p.id > $5::uuid)
ORDER BY p.id
LIMIT $6`, q.Type, q.Namespace, q.Name, likePattern(q.Query), nullIfEmpty(q.After), limit+1)
	if err != nil {
		return store.PURLPage{}, mapErr(err)
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.PURL, error) { return scanPURL(r, true) })
	if err != nil {
		return store.PURLPage{}, mapErr(err)
	}
	page := store.PURLPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextAfter = items[limit-1].ID
	}
	return page, nil
}

// UpsertOSV stores an OSV record and replaces its affected entries in one
// transaction. Records older than the stored modified time are not applied.
// Withdrawn records are kept. Evidence snapshots are never touched.
func (s *Store) UpsertOSV(ctx context.Context, rec store.OSVRecord) (store.UpsertResult, error) {
	if err := validateOSVRecord(rec); err != nil {
		return store.UpsertResult{}, err
	}
	var res store.UpsertResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		res, err = upsertOSV(ctx, tx, rec)
		return err
	})
	return res, err
}

// UpsertOSVBatch commits a bounded set of OSV records in one transaction.
// This is used by full archive ingestion to avoid one fsync per record.
func (s *Store) UpsertOSVBatch(ctx context.Context, records []store.OSVRecord) error {
	if len(records) > 100 {
		return fmt.Errorf("%w: OSV batch exceeds 100 records", store.ErrInvalid)
	}
	for _, rec := range records {
		if err := validateOSVRecord(rec); err != nil {
			return err
		}
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for _, rec := range records {
			if _, err := upsertOSV(ctx, tx, rec); err != nil {
				return err
			}
		}
		return nil
	})
}

func validateOSVRecord(rec store.OSVRecord) error {
	if strings.TrimSpace(rec.ID) == "" || rec.ModifiedAt.IsZero() || rec.FetchedAt.IsZero() {
		return fmt.Errorf("%w: OSV id, modified and fetched_at are required", store.ErrInvalid)
	}
	if !isObject(rec.Raw) {
		return fmt.Errorf("%w: raw OSV record must be a JSON object", store.ErrInvalid)
	}
	seen := map[int]bool{}
	for _, a := range rec.Affected {
		if a.Index < 0 || seen[a.Index] {
			return fmt.Errorf("%w: affected index must be unique and >= 0", store.ErrInvalid)
		}
		seen[a.Index] = true
		if strings.TrimSpace(a.Ecosystem) == "" || strings.TrimSpace(a.Name) == "" {
			return store.ErrInvalid
		}
		if !isObject(a.Affected) {
			return fmt.Errorf("%w: affected entry must be a JSON object", store.ErrInvalid)
		}
		switch a.Mapping {
		case store.PURLExplicit:
			if a.RawPURL == "" || a.PURL == "" {
				return fmt.Errorf("%w: explicit mapping needs raw_purl and purl", store.ErrInvalid)
			}
			p, err := canonicalPURL(a.PURL)
			if err != nil {
				return err
			}
			raw, err := canonicalPURL(a.RawPURL)
			if err != nil {
				return err
			}
			if p.canonical != raw.canonical {
				return store.ErrInvalid
			}
		case store.PURLDerived:
			if a.PURL == "" {
				return fmt.Errorf("%w: derived mapping needs purl", store.ErrInvalid)
			}
		case store.PURLUnavailable:
			if a.PURL != "" {
				return fmt.Errorf("%w: unavailable mapping must not carry a purl", store.ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: unknown purl mapping", store.ErrInvalid)
		}
	}
	return nil
}

func upsertOSV(ctx context.Context, tx pgx.Tx, rec store.OSVRecord) (store.UpsertResult, error) {
	var res store.UpsertResult
	tag, err := tx.Exec(ctx, `
INSERT INTO osv_records (osv_id, modified_at, withdrawn_at, fetched_at, raw_record)
VALUES ($1, $2, $3, $4, $5::jsonb)
ON CONFLICT (osv_id) DO UPDATE SET
    modified_at = EXCLUDED.modified_at, withdrawn_at = EXCLUDED.withdrawn_at,
    fetched_at = EXCLUDED.fetched_at, raw_record = EXCLUDED.raw_record
WHERE osv_records.modified_at <= EXCLUDED.modified_at`,
		rec.ID, rec.ModifiedAt.UTC(), utcPtr(rec.WithdrawnAt), rec.FetchedAt.UTC(), string(rec.Raw))
	if err != nil {
		return res, err
	}
	if tag.RowsAffected() == 0 {
		return res, nil
	}
	res.Applied = true
	if _, err := tx.Exec(ctx, `DELETE FROM osv_affected_packages WHERE osv_id = $1`, rec.ID); err != nil {
		return res, err
	}
	for _, a := range rec.Affected {
		var purlID any
		if a.Mapping != store.PURLUnavailable {
			p, err := ensurePURL(ctx, tx, a.PURL)
			if err != nil {
				return res, err
			}
			purlID = p.ID
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO osv_affected_packages (osv_id, affected_index, ecosystem, name, purl_id, raw_purl, purl_mapping, affected)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
			rec.ID, a.Index, a.Ecosystem, a.Name, purlID, nullIfEmpty(a.RawPURL), string(a.Mapping), string(a.Affected)); err != nil {
			return res, err
		}
	}
	return res, nil
}

func utcPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

// GetOSV returns a stored OSV record with its affected entries.
func (s *Store) GetOSV(ctx context.Context, id string) (store.OSVRecord, error) {
	var rec store.OSVRecord
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT osv_id, modified_at, withdrawn_at, fetched_at, raw_record FROM osv_records WHERE osv_id = $1 FOR SHARE`, id).
			Scan(&rec.ID, &rec.ModifiedAt, &rec.WithdrawnAt, &rec.FetchedAt, &rec.Raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
SELECT a.affected_index, a.ecosystem, a.name, COALESCE(p.canonical_purl, ''), COALESCE(a.raw_purl, ''),
       a.purl_mapping, a.affected, COALESCE(a.purl_id::text, '')
FROM osv_affected_packages a LEFT JOIN purls p ON p.id = a.purl_id
WHERE a.osv_id = $1 ORDER BY a.affected_index`, id)
		if err != nil {
			return err
		}
		rec.Affected, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.OSVAffected, error) {
			var a store.OSVAffected
			var mapping string
			err := r.Scan(&a.Index, &a.Ecosystem, &a.Name, &a.PURL, &a.RawPURL, &mapping, &a.Affected, &a.PURLID)
			a.Mapping = store.PURLMapping(mapping)
			return a, err
		})
		return err
	})
	return rec, err
}

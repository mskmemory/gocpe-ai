-- DESTRUCTIVE: drops every table and all stored data. Use only on disposable
-- databases or after taking a verified backup (see docs/database-design.md).
DROP TABLE source_sync_state;
DROP TABLE target_evidence;
DROP TABLE candidate_evidence;
DROP TABLE evidence_snapshots;
DROP TABLE resolution_candidates;
DROP TABLE resolution_targets;
DROP TABLE resolution_components;
DROP TABLE idempotency_keys;
DROP TABLE resolution_jobs;
DROP TABLE osv_affected_packages;
DROP TABLE osv_records;
DROP TABLE purls;
DROP TABLE nvd_cpe_replacements;
DROP TABLE nvd_cpes;
DROP DOMAIN sha256_hex;

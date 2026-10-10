-- PostgreSQL用 初期設計DDL。既存DBへの移行スクリプトではない。
-- UUIDとSHA-256はGo側で生成する。日時はUTC。
BEGIN;

CREATE TABLE nvd_cpes (
    cpe_name_id uuid PRIMARY KEY,
    cpe_name text NOT NULL,
    cpe_sha256 char(64) NOT NULL UNIQUE,
    part text NOT NULL CHECK (part IN ('a','o','h','*','-')),
    vendor text NOT NULL,
    product text NOT NULL,
    version text NOT NULL,
    attributes jsonb NOT NULL CHECK (jsonb_typeof(attributes) = 'object'),
    titles jsonb NOT NULL CHECK (jsonb_typeof(titles) = 'array'),
    deprecated boolean NOT NULL,
    source_modified_at timestamptz NOT NULL,
    fetched_at timestamptz NOT NULL,
    raw_record jsonb NOT NULL CHECK (jsonb_typeof(raw_record) = 'object')
);
CREATE INDEX nvd_cpes_vendor_product ON nvd_cpes(vendor, product);
CREATE INDEX nvd_cpes_modified ON nvd_cpes(source_modified_at, cpe_name_id);
CREATE TABLE nvd_cpe_replacements (
    cpe_name_id uuid NOT NULL REFERENCES nvd_cpes(cpe_name_id),
    replacement_cpe_name_id uuid NOT NULL,
    PRIMARY KEY (cpe_name_id, replacement_cpe_name_id),
    CHECK (cpe_name_id <> replacement_cpe_name_id)
    -- 置換先が未取得でも保持するため、replacement側にはFKを付けない。
);

CREATE TABLE purls (
    id uuid PRIMARY KEY,
    canonical_purl text NOT NULL,
    purl_sha256 char(64) NOT NULL UNIQUE,
    normalization_version text NOT NULL,
    type text NOT NULL,
    namespace text,
    name text NOT NULL,
    version text,
    qualifiers jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(qualifiers) = 'object'),
    subpath text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX purls_identity ON purls(type, namespace, name);
-- purlsへの挿入自体は外部確認を意味しない。OSV確認は以下の関連表で表す。
CREATE TABLE osv_records (
    osv_id text PRIMARY KEY,
    modified_at timestamptz NOT NULL,
    withdrawn_at timestamptz,
    fetched_at timestamptz NOT NULL,
    raw_record jsonb NOT NULL CHECK (jsonb_typeof(raw_record) = 'object')
);
CREATE TABLE osv_affected_packages (
    osv_id text NOT NULL REFERENCES osv_records(osv_id),
    affected_index integer NOT NULL CHECK (affected_index >= 0),
    ecosystem text NOT NULL,
    name text NOT NULL,
    purl_id uuid REFERENCES purls(id),
    raw_purl text,
    purl_mapping text NOT NULL CHECK (purl_mapping IN ('explicit','derived','unavailable')),
    affected jsonb NOT NULL CHECK (jsonb_typeof(affected) = 'object'),
    PRIMARY KEY (osv_id, affected_index),
    CHECK ((purl_mapping = 'unavailable') = (purl_id IS NULL))
);
CREATE INDEX osv_affected_identity ON osv_affected_packages(ecosystem, name);
CREATE INDEX osv_affected_purl ON osv_affected_packages(purl_id) WHERE purl_id IS NOT NULL;

CREATE TABLE resolution_jobs (
    id uuid PRIMARY KEY,
    owner_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('queued','running','cancelling','completed','partial','failed','cancelled')),
    provider text NOT NULL CHECK (provider IN ('openai','gemini','claude','deepseek')),
    model text NOT NULL,
    options jsonb NOT NULL,
    input_kind text NOT NULL CHECK (input_kind IN ('packages','sbom')),
    input_document jsonb NOT NULL,
    input_sha256 char(64) NOT NULL,
    config_sha256 char(64) NOT NULL,
    run_metadata jsonb NOT NULL,
    total integer NOT NULL CHECK (total > 0 AND total <= 1000),
    processed integer NOT NULL DEFAULT 0 CHECK (processed >= 0 AND processed <= total),
    errors jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(errors) = 'array'),
    lease_token uuid,
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    expires_at timestamptz NOT NULL,
    UNIQUE (owner_id, id),
    CHECK (expires_at > created_at),
    CHECK ((status IN ('completed','partial','failed','cancelled')) = (finished_at IS NOT NULL)),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);
CREATE INDEX jobs_owner_created ON resolution_jobs(owner_id, created_at DESC, id);
CREATE INDEX jobs_queue ON resolution_jobs(created_at, id) WHERE status = 'queued';
CREATE INDEX jobs_lease ON resolution_jobs(lease_until) WHERE status IN ('running','cancelling');
CREATE INDEX jobs_expiry ON resolution_jobs(expires_at);
CREATE TABLE idempotency_keys (
    owner_id text NOT NULL,
    key text NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
    request_sha256 char(64) NOT NULL,
    job_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (owner_id, key),
    FOREIGN KEY (owner_id, job_id) REFERENCES resolution_jobs(owner_id, id) ON DELETE CASCADE
);
CREATE INDEX idempotency_expiry ON idempotency_keys(expires_at);

CREATE TABLE resolution_components (
    job_id uuid NOT NULL REFERENCES resolution_jobs(id) ON DELETE CASCADE,
    component_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    source_pointer text NOT NULL,
    normalized_input jsonb NOT NULL,
    raw_values jsonb NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','running','done')),
    errors jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(errors) = 'array'),
    PRIMARY KEY (job_id, component_id),
    UNIQUE (job_id, ordinal)
);
CREATE TABLE resolution_targets (
    job_id uuid NOT NULL,
    component_id text NOT NULL,
    target text NOT NULL CHECK (target IN ('cpe','purl')),
    decision text NOT NULL CHECK (decision IN ('accepted','review_required','unresolved')),
    reason_codes jsonb NOT NULL CHECK (jsonb_typeof(reason_codes) = 'array'),
    lookup jsonb NOT NULL CHECK (jsonb_typeof(lookup) = 'object'),
    PRIMARY KEY (job_id, component_id, target),
    FOREIGN KEY (job_id, component_id) REFERENCES resolution_components(job_id, component_id) ON DELETE CASCADE
);
CREATE TABLE resolution_candidates (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL,
    component_id text NOT NULL,
    target text NOT NULL,
    rank integer NOT NULL CHECK (rank BETWEEN 1 AND 5),
    value text NOT NULL,
    origin text NOT NULL CHECK (origin IN ('sbom','ai','nvd','osv')),
    scope text NOT NULL CHECK (scope IN ('product','package','version')),
    verification_status text NOT NULL CHECK (verification_status IN ('confirmed','no_evidence','unsupported','error','not_checked')),
    identity_status text NOT NULL CHECK (identity_status IN ('strong','plausible','ambiguous','mismatch','insufficient')),
    version_status text NOT NULL CHECK (version_status IN ('matched','unknown','conflict','not_checked')),
    verification jsonb NOT NULL,
    identity_detail jsonb NOT NULL,
    selected boolean NOT NULL DEFAULT false,
    cpe_name_id uuid REFERENCES nvd_cpes(cpe_name_id),
    purl_id uuid REFERENCES purls(id),
    UNIQUE (job_id, component_id, target, rank),
    UNIQUE (job_id, id),
    FOREIGN KEY (job_id, component_id, target) REFERENCES resolution_targets(job_id, component_id, target) ON DELETE CASCADE,
    CHECK ((target = 'cpe' AND purl_id IS NULL) OR (target = 'purl' AND cpe_name_id IS NULL)),
    CHECK (NOT selected OR (verification_status = 'confirmed' AND identity_status = 'strong')),
    CHECK (NOT selected OR scope <> 'version' OR version_status = 'matched')
);
CREATE INDEX candidates_cpe ON resolution_candidates(cpe_name_id) WHERE cpe_name_id IS NOT NULL;
CREATE INDEX candidates_purl ON resolution_candidates(purl_id) WHERE purl_id IS NOT NULL;

CREATE TABLE evidence_snapshots (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES resolution_jobs(id) ON DELETE CASCADE,
    source text NOT NULL CHECK (source IN ('nvd','osv')),
    source_record_id text,
    reference_url text,
    query jsonb NOT NULL,
    observed_at timestamptz NOT NULL,
    response_sha256 char(64) NOT NULL,
    scope text NOT NULL CHECK (scope IN ('product','package','version')),
    match_kind text NOT NULL CHECK (match_kind IN ('cpe_registration','purl_match','ecosystem_name_match','lookup')),
    from_cache boolean NOT NULL,
    snapshot jsonb NOT NULL,
    UNIQUE (job_id, id)
    -- 履歴はコピーを保持し、最新の辞書行には依存しない。
);
CREATE TABLE candidate_evidence (
    job_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    PRIMARY KEY (job_id, candidate_id, evidence_id),
    FOREIGN KEY (job_id, candidate_id) REFERENCES resolution_candidates(job_id, id) ON DELETE CASCADE,
    FOREIGN KEY (job_id, evidence_id) REFERENCES evidence_snapshots(job_id, id) ON DELETE CASCADE
);
CREATE TABLE target_evidence (
    job_id uuid NOT NULL,
    component_id text NOT NULL,
    target text NOT NULL,
    evidence_id uuid NOT NULL,
    PRIMARY KEY (job_id, component_id, target, evidence_id),
    FOREIGN KEY (job_id, component_id, target) REFERENCES resolution_targets(job_id, component_id, target) ON DELETE CASCADE,
    FOREIGN KEY (job_id, evidence_id) REFERENCES evidence_snapshots(job_id, id) ON DELETE CASCADE
);
CREATE TABLE source_sync_state (
    source text NOT NULL CHECK (source IN ('nvd','osv')),
    stream text NOT NULL,
    watermark timestamptz,
    window_start timestamptz,
    window_end timestamptz,
    cursor jsonb,
    status text NOT NULL CHECK (status IN ('idle','running','failed')),
    lease_token uuid,
    lease_until timestamptz,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (source, stream),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
    CHECK (window_end IS NULL OR window_start <= window_end)
);
COMMIT;

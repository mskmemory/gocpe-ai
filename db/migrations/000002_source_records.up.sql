CREATE TABLE source_records (
    source text NOT NULL CHECK (source = 'nvd'),
    stream text NOT NULL CHECK (stream IN ('cve','match','history','source')),
    record_id text NOT NULL CHECK (record_id <> ''),
    modified_at timestamptz NOT NULL,
    fetched_at timestamptz NOT NULL,
    raw_record jsonb NOT NULL CHECK (jsonb_typeof(raw_record) = 'object'),
    PRIMARY KEY (source, stream, record_id)
);

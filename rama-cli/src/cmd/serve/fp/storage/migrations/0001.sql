-- Each authorization domain has independent identities, counts and quotas.
CREATE TABLE fp_v2.profiles (
    authorized BOOLEAN NOT NULL,
    id BYTEA NOT NULL CHECK (octet_length(id) = 32),
    canonical BYTEA NOT NULL,
    PRIMARY KEY (authorized, id)
);
CREATE TABLE fp_v2.flows (
    authorized BOOLEAN NOT NULL,
    profile_id BYTEA NOT NULL,
    id BYTEA NOT NULL CHECK (octet_length(id) = 32),
    canonical BYTEA NOT NULL,
    PRIMARY KEY (authorized, profile_id, id),
    FOREIGN KEY (authorized, profile_id) REFERENCES fp_v2.profiles ON DELETE CASCADE
);
CREATE TABLE fp_v2.values (
    authorized BOOLEAN NOT NULL,
    id BYTEA NOT NULL CHECK (octet_length(id) = 32),
    domain INTEGER NOT NULL CHECK (domain BETWEEN 1 AND 65535),
    canonical BYTEA NOT NULL,
    PRIMARY KEY (authorized, id)
);
CREATE TABLE fp_v2.structures (
    authorized BOOLEAN NOT NULL,
    id BYTEA NOT NULL CHECK (octet_length(id) = 32),
    normalizer INTEGER NOT NULL CHECK (normalizer > 0),
    slot INTEGER NOT NULL CHECK (slot >= 0),
    canonical BYTEA NOT NULL,
    PRIMARY KEY (authorized, id)
);
CREATE TABLE fp_v2.buckets (
    authorized BOOLEAN NOT NULL,
    scope BYTEA NOT NULL CHECK (octet_length(scope) = 32),
    day BIGINT NOT NULL CHECK (day BETWEEN 0 AND 4294967295),
    profile_id BYTEA NOT NULL,
    flow_id BYTEA,
    structure_id BYTEA NOT NULL,
    -- Scope bytes include authorization, profile, optional flow and connection context.
    scope_canonical BYTEA NOT NULL,
    domain INTEGER NOT NULL CHECK (domain BETWEEN 1 AND 65535),
    format_version INTEGER NOT NULL CHECK (format_version > 0),
    total BIGINT NOT NULL CHECK (total >= 0),
    untracked BIGINT NOT NULL CHECK (untracked BETWEEN 0 AND total),
    retained_bytes BIGINT NOT NULL CHECK (retained_bytes >= 0),
    PRIMARY KEY (authorized, scope, day),
    FOREIGN KEY (authorized, profile_id) REFERENCES fp_v2.profiles,
    FOREIGN KEY (authorized, profile_id, flow_id) REFERENCES fp_v2.flows,
    FOREIGN KEY (authorized, structure_id) REFERENCES fp_v2.structures
);
CREATE INDEX buckets_profile_day ON fp_v2.buckets (authorized, profile_id, day);
CREATE TABLE fp_v2.literal_counts (
    authorized BOOLEAN NOT NULL,
    scope BYTEA NOT NULL,
    day BIGINT NOT NULL,
    value_id BYTEA NOT NULL,
    count BIGINT NOT NULL CHECK (count > 0),
    PRIMARY KEY (authorized, scope, day, value_id),
    FOREIGN KEY (authorized, scope, day) REFERENCES fp_v2.buckets ON DELETE CASCADE,
    FOREIGN KEY (authorized, value_id) REFERENCES fp_v2.values
);
CREATE TABLE fp_v2.samples (
    authorized BOOLEAN NOT NULL,
    scope BYTEA NOT NULL,
    day BIGINT NOT NULL,
    run BYTEA NOT NULL CHECK (octet_length(run) = 16),
    sequence NUMERIC(20, 0) NOT NULL CHECK (sequence BETWEEN 1 AND 18446744073709551615),
    priority BYTEA NOT NULL CHECK (octet_length(priority) = 32),
    value_id BYTEA NOT NULL,
    PRIMARY KEY (authorized, scope, day, run, sequence),
    FOREIGN KEY (authorized, scope, day) REFERENCES fp_v2.buckets ON DELETE CASCADE,
    FOREIGN KEY (authorized, value_id) REFERENCES fp_v2.values
);
CREATE INDEX samples_priority ON fp_v2.samples (authorized, scope, day, priority, run, sequence);
CREATE TABLE fp_v2.runs (
    authorized BOOLEAN NOT NULL,
    id BYTEA NOT NULL CHECK (octet_length(id) = 16),
    created_day BIGINT NOT NULL CHECK (created_day BETWEEN 0 AND 4294967295),
    checkpoint JSONB NOT NULL,
    PRIMARY KEY (authorized, id)
);
-- Writers lock this row before applying bounded quota deltas in their transaction.
CREATE TABLE fp_v2.quotas (
    authorized BOOLEAN PRIMARY KEY,
    watermark BIGINT NOT NULL CHECK (watermark BETWEEN 0 AND 4294967295),
    profiles BIGINT NOT NULL CHECK (profiles >= 0),
    flows BIGINT NOT NULL CHECK (flows >= 0),
    structures BIGINT NOT NULL CHECK (structures >= 0),
    buckets BIGINT NOT NULL CHECK (buckets >= 0),
    runs BIGINT NOT NULL CHECK (runs >= 0),
    canonical_bytes BIGINT NOT NULL CHECK (canonical_bytes >= 0)
);
INSERT INTO fp_v2.quotas VALUES (FALSE, 0, 0, 0, 0, 0, 0, 0), (TRUE, 0, 0, 0, 0, 0, 0, 0);
CREATE TABLE fp_v2.legacy_imports (
    authorized BOOLEAN NOT NULL,
    source_table TEXT NOT NULL,
    source_key BYTEA NOT NULL,
    row_digest BYTEA NOT NULL CHECK (octet_length(row_digest) = 32),
    imported_day BIGINT NOT NULL CHECK (imported_day BETWEEN 0 AND 4294967295),
    PRIMARY KEY (authorized, source_table, source_key, row_digest)
);

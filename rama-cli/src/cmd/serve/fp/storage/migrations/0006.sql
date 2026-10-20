-- Rejected source revisions contain only hashes and static disposition labels.
-- Writers serialize on the partition quota row and cap these separately at the
-- configured active-run limit. Maintenance retires them with the same horizon.
CREATE TABLE fp_v2.legacy_rejections (
    authorized BOOLEAN NOT NULL,
    source_table TEXT NOT NULL,
    source_key BYTEA NOT NULL CHECK (octet_length(source_key) = 32),
    row_digest BYTEA NOT NULL CHECK (octet_length(row_digest) = 32),
    rejected_day BIGINT NOT NULL CHECK (rejected_day BETWEEN 0 AND 4294967295),
    category TEXT NOT NULL CHECK (category IN ('invalid', 'oversize', 'expired')),
    CHECK ((authorized AND source_table = 'ua-profiles')
        OR (NOT authorized AND source_table = 'public-ua-profiles')),
    PRIMARY KEY (authorized, source_table, source_key)
);
CREATE INDEX legacy_rejection_expiry ON fp_v2.legacy_rejections (authorized, rejected_day, source_key);

ALTER TABLE fp_v2.quotas ADD COLUMN legacy_rejections BIGINT NOT NULL DEFAULT 0
    CHECK (legacy_rejections >= 0);

-- Keep admission constant-time and account for every owned deletion path.
CREATE FUNCTION fp_v2.count_legacy_rejection() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE fp_v2.quotas SET legacy_rejections = legacy_rejections + 1
            WHERE authorized = NEW.authorized;
    ELSE
        UPDATE fp_v2.quotas SET legacy_rejections = legacy_rejections - 1
            WHERE authorized = OLD.authorized;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER count_legacy_rejection AFTER INSERT OR DELETE ON fp_v2.legacy_rejections
    FOR EACH ROW EXECUTE FUNCTION fp_v2.count_legacy_rejection();

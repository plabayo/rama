-- Each new legacy checkpoint owns one bounded ingestion run. Retiring that run
-- also retires its import checkpoint; expired source timestamps stay inadmissible.
ALTER TABLE fp_v2.legacy_imports ADD COLUMN run_id BYTEA
    CHECK (run_id IS NULL OR octet_length(run_id) = 16);
ALTER TABLE fp_v2.legacy_imports ADD CONSTRAINT legacy_import_run
    FOREIGN KEY (authorized, run_id) REFERENCES fp_v2.runs (authorized, id) ON DELETE CASCADE;
CREATE UNIQUE INDEX legacy_import_run_unique ON fp_v2.legacy_imports (authorized, run_id)
    WHERE run_id IS NOT NULL;

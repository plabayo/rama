-- Shared values are reclaimed only after their last counter/sample reference ends.
CREATE INDEX literal_counts_value ON fp_v2.literal_counts (authorized, value_id);
CREATE INDEX samples_value ON fp_v2.samples (authorized, value_id);
-- Retention and orphan scans remain within one authorization partition.
CREATE INDEX buckets_retention ON fp_v2.buckets (authorized, day);
CREATE INDEX runs_retention ON fp_v2.runs (authorized, created_day);
CREATE INDEX buckets_structure ON fp_v2.buckets (authorized, structure_id);
CREATE INDEX buckets_flow ON fp_v2.buckets (authorized, profile_id, flow_id);

ALTER TABLE fp_v2.quotas ADD COLUMN interned_values BIGINT NOT NULL DEFAULT 0 CHECK (interned_values >= 0);
ALTER TABLE fp_v2.quotas ADD COLUMN sampler_seed BYTEA CHECK (octet_length(sampler_seed) = 32);

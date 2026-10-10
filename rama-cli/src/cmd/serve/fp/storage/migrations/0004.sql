-- Older buckets have no retained evidence for untracked distinct values.
ALTER TABLE fp_v2.buckets ADD COLUMN untracked_distinct JSONB NOT NULL DEFAULT
    '{"values":[],"saturated":false,"history_known":false}'::jsonb;

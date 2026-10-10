-- Existing observations predate explicit loss accounting.
ALTER TABLE fp_v2.buckets
    ADD COLUMN dropped_oversize BIGINT NOT NULL DEFAULT 0 CHECK (dropped_oversize >= 0),
    ADD COLUMN dropped_retention BIGINT NOT NULL DEFAULT 0 CHECK (dropped_retention >= 0),
    ADD COLUMN history_known BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT observation_loss_accounting CHECK (
        dropped_oversize <= untracked AND dropped_retention <= untracked - dropped_oversize
    );

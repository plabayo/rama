-- Imported revisions have a separate bound and never consume live run capacity.
ALTER TABLE fp_v2.runs ADD COLUMN legacy BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE fp_v2.quotas ADD COLUMN legacy_runs BIGINT NOT NULL DEFAULT 0 CHECK (legacy_runs >= 0);
UPDATE fp_v2.runs r SET legacy=TRUE WHERE EXISTS
    (SELECT 1 FROM fp_v2.legacy_imports l WHERE l.authorized=r.authorized AND l.run_id=r.id);
UPDATE fp_v2.quotas q SET legacy_runs=c.n, runs=q.runs-c.n
    FROM (SELECT authorized,count(*) AS n FROM fp_v2.runs WHERE legacy GROUP BY authorized) c
    WHERE q.authorized=c.authorized;
ALTER TABLE fp_v2.legacy_imports ADD CHECK (octet_length(source_key) = 32);
ALTER TABLE fp_v2.legacy_imports ADD CHECK ((authorized AND source_table = 'ua-profiles')
    OR (NOT authorized AND source_table = 'public-ua-profiles'));

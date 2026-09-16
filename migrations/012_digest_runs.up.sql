-- 012_digest_runs.up.sql
--
-- The digest history: one row per digest this deployment has produced on
-- a schedule, so the console can list past ones.
--
-- cryden owns no scheduling concept at all. WeeklyDigest/DigestSince
-- build a report from the audit table and return a string; there is no
-- cron, no run record, and nothing anywhere in the engine that remembers
-- a digest was ever generated. Any "past digests" list is therefore this
-- repo's own infrastructure, and this is its table.
--
-- The digest TEXT is stored rather than re-derivable counts, which is a
-- deliberate choice about what this table is for. A digest is a report
-- on a window that has ended: the events it counted are still in the
-- audit table, but re-running the same query later would not reproduce
-- it, because "last seven days" is anchored to when the digest was
-- built. Storing the rendered text is what makes reading a past digest
-- the same experience as reading a fresh one, and what makes the row
-- evidence of what was actually reported rather than a recipe for
-- something similar.
--
-- The two window columns are stored alongside it because the text alone
-- cannot be sorted, filtered or compared, and an operator asking "which
-- windows did we cover" should not have to parse English out of a report
-- to find out.

CREATE TABLE digest_runs (
    id          BIGSERIAL PRIMARY KEY,

    -- The window this digest covers: [window_start, window_end). Stored
    -- as the inclusive start and the instant the digest was built, which
    -- is what DigestSince was asked for and what its own text prints, so
    -- the row and the report never disagree about which week they cover.
    window_start TIMESTAMPTZ NOT NULL,
    window_end   TIMESTAMPTZ NOT NULL,

    -- When this row was written. Distinct from window_end on purpose:
    -- a run that is replayed or backfilled after an outage covers a
    -- window that closed before the digest was made, and collapsing the
    -- two would lose exactly that.
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The rendered report, exactly as DigestSince returned it.
    digest_text  TEXT NOT NULL
);

-- The listing's only view: newest first. The id tiebreak is what makes
-- the order total — two runs can share a timestamp, and an unstable sort
-- would show them in a different order on each request.
CREATE INDEX idx_digest_runs_generated ON digest_runs(generated_at DESC, id DESC);

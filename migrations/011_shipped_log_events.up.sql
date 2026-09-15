-- 011_shipped_log_events.up.sql
--
-- The "shipped events" log: a record of the log records this
-- deployment's cloud-logging sink was handed. cryden calls a
-- logger.Logger and nothing more — it holds no vendor client, makes no
-- outbound call, and keeps no history of what it logged — so the
-- queryable copy is this repo's own table.
--
-- What lands here is the REDACTED, FILTERED copy, not the raw one. The
-- sink is wired inside the composition cryden's own package doc
-- prescribes, as
--
--   logger.NewMultiLogger(
--       logger.NewConsoleJSONLogger(),                  -- full detail, stdout
--       logger.NewLevelFilter(                          -- what leaves the box
--           logger.NewMaskingRedactor(shipSink),
--           level,
--       ),
--   )
--
-- so the row holds what a hosted aggregator would have received: the
-- IP address replaced by [redacted] or a keyed digest, and everything
-- below LOG_LEVEL never reaching the sink to be written at all. That is
-- the property that makes this table a stand-in for a vendor rather
-- than a second, different log beside one.

CREATE TABLE shipped_log_events (
    id       BIGSERIAL PRIMARY KEY,

    -- One of debug/info/warn/error, written from logger.Level's own
    -- String() so a record reads the same here as in the console line
    -- and in the API's own level= filter. TEXT rather than an enum, for
    -- the same reason webhook_deliveries.event_type is: this repo must
    -- not need a migration to learn about a level the engine adds.
    level    TEXT NOT NULL,

    -- The record's message. cryden's messages are constant strings with
    -- every variable part in fields, which is what makes a level filter
    -- and a redactor sufficient rather than heuristic.
    message  TEXT NOT NULL,

    -- The record's structured fields, redacted. Defaulted rather than
    -- nullable so a read never has to distinguish "no fields" from
    -- "NULL", which a console would render the same way anyway.
    fields   JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Which sink wrote the row. Only one value is written today
    -- ("database"), and it is recorded anyway: a deployment that adds a
    -- second reader of the same Logger — a file, an OpenTelemetry
    -- collector — would otherwise have its rows indistinguishable from
    -- these in a table it shares.
    sink     TEXT NOT NULL,

    shipped_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The admin listing's default view: newest first, unfiltered.
CREATE INDEX idx_shipped_log_events_shipped ON shipped_log_events(shipped_at DESC);

-- And its filtered view. rank-by-name is not answerable from an index on
-- a TEXT column, so the query passes the set of acceptable level names
-- and this index serves the equality plus the ordering within it.
CREATE INDEX idx_shipped_log_events_level ON shipped_log_events(level, shipped_at DESC);

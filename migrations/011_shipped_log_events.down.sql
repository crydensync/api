-- 011_shipped_log_events.down.sql

DROP INDEX IF EXISTS idx_shipped_log_events_level;
DROP INDEX IF EXISTS idx_shipped_log_events_shipped;
DROP TABLE IF EXISTS shipped_log_events;

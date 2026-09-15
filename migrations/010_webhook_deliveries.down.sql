-- 010_webhook_deliveries.down.sql
--
-- Drops the indexes with the table rather than relying on the table drop
-- to take them: this repo's migrations are applied by hand as often as
-- by a runner, and an explicit drop is what makes the file safe to run
-- twice.

DROP INDEX IF EXISTS idx_webhook_deliveries_created;
DROP INDEX IF EXISTS idx_webhook_deliveries_due;
DROP TABLE IF EXISTS webhook_deliveries;

-- 010_webhook_deliveries.up.sql
--
-- The delivery log for engine webhooks: one row per event the host
-- chose to deliver, whether or not it has been delivered yet. This is
-- the queue AND the record — cryden calls Config.Webhooks synchronously
-- on the request path (see notify.WebhookSender's own doc comment), so
-- the only implementation worth deploying is an enqueue, and a queue
-- that is not also queryable cannot answer the question the log exists
-- for: "was that lockout actually announced?"
--
-- user_id carries NO foreign key, deliberately. This is the same
-- reasoning audit_events and login_attempts are built on: a delivery is
-- evidence about an account, and evidence about a deleted account keeps
-- its value without the account. ON DELETE CASCADE here would mean
-- deleting a user silently rewrites the history of what that deletion
-- was reported to have triggered.
--
-- There is no "pending" row for a delivery that could not be queued:
-- the row IS the queue.

CREATE TABLE webhook_deliveries (
    -- The row's own identity, and the queue's ordering. A surrogate
    -- rather than the engine's event id as the primary key, because
    -- that id is not guaranteed to be present: cryden generates it with
    -- crypto/rand and, on a generator failure, deliberately delivers the
    -- event with an EMPTY id rather than dropping it ("the delivery is
    -- worth more than its idempotency key" — see webhooks.go). Keying on
    -- it would turn that decision into a unique-constraint violation and
    -- lose exactly the event the engine went out of its way to keep.
    id           BIGSERIAL PRIMARY KEY,

    -- The engine's idempotency key for this occurrence, sent to the
    -- receiver as X-Cryden-Event-Id. Indexed, not unique: it is the
    -- receiver's dedupe key, and the engine's contract explicitly allows
    -- it to be empty, where two empty values are two different events.
    event_id     TEXT NOT NULL DEFAULT '',

    -- The store.AuditEventType that was recorded, as a string. Not an
    -- enum: this repo must not need a migration to learn about an event
    -- type the engine adds.
    event_type   TEXT NOT NULL,
    user_id      UUID,
    ip           TEXT,

    -- The event body, as it goes on the wire. The delivery worker reads
    -- this column back out and sends those bytes unchanged — it does not
    -- rebuild the body from the other columns, because a second
    -- implementation of the payload is free to drift from what the
    -- console shows an operator, and "show me what we sent that
    -- endpoint" is the question this log exists to answer.
    --
    -- JSONB rather than TEXT does not cost that exactness, which is
    -- worth spelling out since it is not obvious: Postgres emits a
    -- JSONB value with its keys in a deterministic order, so reading
    -- the column back twice yields identical bytes. The bytes signed
    -- and the bytes displayed are the same bytes, and a receiver
    -- checking a live delivery against the log computes the same
    -- digest. That also means the digest is over the NORMALISED body,
    -- not over whatever key order the sender happened to emit.
    payload      JSONB NOT NULL,

    -- pending -> in_flight -> delivered
    --                      -> pending (retry, next_attempt_at pushed out)
    --                      -> failed  (out of attempts, or abandoned)
    status       TEXT NOT NULL DEFAULT 'pending',

    -- Attempts STARTED, incremented when a row is claimed rather than
    -- when it fails. A process that died mid-delivery still made the
    -- attempt — the receiver may well have got it, since at-least-once
    -- is the only promise a queue can make. It follows that a crash can
    -- leave this one above the configured maximum; that is preferred to
    -- the alternative, a row stuck at "in flight" that nothing will ever
    -- finish or report on.
    attempts     INT NOT NULL DEFAULT 0,

    response_code INT,
    error        TEXT,
    duration_ms  INT,

    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- When this row next becomes claimable. Set to now() at insert, so a
    -- fresh event is due immediately.
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Stamped when a worker claims the row and cleared whenever it
    -- resolves it. A row left in_flight past a staleness bound is one
    -- whose worker stopped mid-delivery, and is reclaimed rather than
    -- stranded.
    claimed_at   TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ
);

-- The claim query's index, and the one an admin listing filtered by
-- status uses. Leading with status makes the partial scan cheap: the
-- rows a worker wants are the pending ones, and this never walks the
-- delivered history that will be the bulk of the table.
CREATE INDEX idx_webhook_deliveries_due ON webhook_deliveries(status, next_attempt_at);

-- The admin listing's default view — newest first, unfiltered.
CREATE INDEX idx_webhook_deliveries_created ON webhook_deliveries(created_at DESC);

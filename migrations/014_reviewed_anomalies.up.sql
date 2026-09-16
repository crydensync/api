-- 014_reviewed_anomalies.up.sql
--
-- What a human decided about an event cryden flagged. The engine records
-- the signals (anomaly_detected, credential_stuffing_detected — see its
-- security.AnomalySignal) and has no concept of anyone having looked at
-- one; this table is that concept. It is this repo's own, and cryden's
-- audit_events rows are never touched to record a review: the evidence
-- reads the same before and after one, which is the entire reason a
-- review is a row here and not a write there.
--
-- The primary key is the audit event's own id rather than a surrogate.
-- That is the identity the console shows and the identity an operator
-- acts on, so a second id would be a second thing to look up and a
-- second thing to get wrong.
--
-- status is a column and 'unreviewed' is one of its values, rather than
-- an absence of rows. Two things fall out of that and both are wanted:
-- dismissing a flagged event keeps the evidence (which is what makes it
-- a dismissal and not a delete), and withdrawing a judgement keeps the
-- record that the first judgement was made and by whom. Nothing in this
-- api deletes from this table.

CREATE TABLE reviewed_anomalies (
    -- The foreign key is deliberate, and it is the one place this table
    -- reads cryden's schema: it makes the database itself refuse a
    -- review of an event that does not exist, which is a check this
    -- repo cannot make in Go — cryden exposes no lookup-by-event-id,
    -- only list/search by user or type. It constrains writes here and
    -- never there, and CASCADE is right in the only direction that can
    -- matter: an event that is gone has nothing to annotate.
    event_id    UUID PRIMARY KEY REFERENCES audit_events(id) ON DELETE CASCADE,
    -- 'confirmed' (a real incident), 'dismissed' (a false positive) or
    -- 'unreviewed' (a judgement withdrawn). CHECK rather than free
    -- text, so a status this api does not define cannot be stored by
    -- any writer, including one that is not this package.
    status      TEXT NOT NULL CHECK (status IN ('confirmed', 'dismissed', 'unreviewed')),
    -- What the reviewer wrote. Empty is the normal case: this is a
    -- note, not a justification anyone is required to give.
    note        TEXT NOT NULL DEFAULT '',
    -- The operator who made the call, taken from the token this api
    -- issued. Nullable and ON DELETE SET NULL, matching
    -- audit_events.user_id and for the same reason: a review has to
    -- outlive the account that made it, and losing the attribution is
    -- better than losing the judgement.
    reviewer_id UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- No index beyond the primary key. Every read here is by event_id (the
-- PK) and every write is an upsert on it, so an index on status or
-- reviewer_id would be one nothing reads.

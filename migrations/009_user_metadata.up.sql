-- 009_user_metadata.up.sql
--
-- Arbitrary per-user metadata, owned by this api layer. cryden's own
-- store.User deliberately has no metadata concept and will not gain
-- one (see cryden's docs/design-decisions.md) — so the row that a
-- console maps into JWT claims lives here, keyed off the engine's own
-- user id, exactly like operators (003) does.
--
-- The shape is one row per key rather than one JSON blob per user.
-- A blob would make "set field X" a read-modify-write, so two console
-- operators saving at the same moment would silently lose one edit;
-- per-key rows make every write a single upsert and every delete a
-- single statement, with no window between them.
--
-- value is JSONB, not TEXT, and that is load-bearing rather than
-- stylistic: everything in this table becomes a JWT claim, and a claim
-- has to marshal to JSON. Storing JSON means a value that could not be
-- a claim cannot be stored in the first place.

CREATE TABLE user_metadata (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The claim name this value will appear under. A non-reserved
    -- keyword in Postgres, so it needs no quoting.
    key        TEXT NOT NULL,
    value      JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Composite rather than a surrogate id: (user_id, key) is the real
    -- identity here, and it is also the index every read uses.
    PRIMARY KEY (user_id, key)
);

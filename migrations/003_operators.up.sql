-- 003_operators.up.sql
--
-- Operators are console/admin accounts, deliberately owned by this api
-- layer rather than by cryden itself. cryden's own store.User has no
-- role or permission concept by design (see cryden's
-- docs/design-decisions.md: authorization is a host decision, the
-- engine only owns authentication mechanics), so "who may use the
-- admin console" is a decision this layer makes on top, not something
-- the engine tracks.
--
-- role is a plain string, not an enum, for the same reason
-- OAuthIdentity.Provider is a plain string in cryden itself: a new
-- role should never require a migration.

CREATE TABLE operators (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

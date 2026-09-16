-- 013_settings.up.sql
--
-- Runtime configuration this api layer owns, for the values an operator
-- changes through a settings screen rather than a redeploy.
--
-- Why a table and not env vars: cryden's ai.LLMProvider and
-- ai.QueryableStore are Go interfaces a host implements in code, and
-- everything else in this repo is configured by environment variable at
-- startup. That works for a threshold. It does not work for an LLM API
-- key an operator rotates, or for pointing the AI query surface at a
-- second, read-only database — both are things a deployment wants to
-- change without a restart and without shell access to the box.
--
-- value is BYTEA, not TEXT or JSONB, and that is the point of the table
-- rather than a storage detail. Every credential written here — an API
-- key, a database password — is sealed with AES-GCM before it reaches
-- this store (see settings/secrets.go), so the bytes the database holds
-- are ciphertext and nothing else. A TEXT column would invite a caller to
-- write a readable value "just this once"; a BYTEA column holding
-- authenticated ciphertext means a plaintext credential in this table is
-- not a mistake someone can make by choosing the wrong helper.
--
-- There is no user_id and no created_by. This is deployment-wide
-- configuration, not per-user data, and the audit trail for changing it
-- is the engine's own audit table — the handlers behind these rows are
-- admin-only and every write is attributable to a token this api issued.

CREATE TABLE settings (
    -- A short, stable name ("llm_provider", "database_provider"). Not a
    -- surrogate id: the name IS the identity, and a lookup by anything
    -- else would be a lookup by something a caller had to be told.
    key        TEXT PRIMARY KEY,
    -- Authenticated ciphertext. Never plaintext — see above.
    value      BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

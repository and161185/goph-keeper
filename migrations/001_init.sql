-- +goose Up
-- Enable uuid + crypto. Use one of them depending on your image.
CREATE EXTENSION IF NOT EXISTS pgcrypto;      -- gen_random_uuid()
-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp"; -- uuid_generate_v4()

-- USERS
CREATE TABLE IF NOT EXISTS users (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username     text UNIQUE NOT NULL,
  pwd_hash     bytea NOT NULL,
  salt_auth    bytea NOT NULL,
  kek_salt     bytea NOT NULL,
  wrapped_dek  bytea NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- ITEMS (opaque encrypted blobs, versioned, tombstoned)
CREATE TABLE IF NOT EXISTS items (
  id          uuid PRIMARY KEY,  -- client-generated
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blob_enc    bytea NOT NULL,    -- AEAD opaque {type,meta,data}
  ver         bigint NOT NULL CHECK (ver >= 0),
  deleted     boolean NOT NULL DEFAULT false,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Fast lookups per user and sync by version.
CREATE INDEX IF NOT EXISTS idx_items_user ON items(user_id);
CREATE INDEX IF NOT EXISTS idx_items_user_ver ON items(user_id, ver);

-- updated_at trigger function
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_items_updated_at ON items;
CREATE TRIGGER trg_items_updated_at
BEFORE UPDATE ON items
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Helpful view for debugging (no plaintext!)
CREATE OR REPLACE VIEW v_item_stats AS
SELECT
  user_id,
  count(*) AS total,
  count(*) FILTER (WHERE deleted) AS deleted,
  max(ver) AS max_ver
FROM items
GROUP BY user_id;

-- +goose Down
DROP VIEW IF EXISTS v_item_stats;
DROP TRIGGER IF EXISTS trg_items_updated_at ON items;
DROP FUNCTION IF EXISTS set_updated_at();
DROP INDEX IF EXISTS idx_items_user_ver;
DROP INDEX IF EXISTS idx_items_user;
DROP TABLE IF EXISTS items;
DROP TABLE IF EXISTS users;


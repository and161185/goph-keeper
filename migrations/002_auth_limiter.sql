-- +goose Up
CREATE TABLE IF NOT EXISTS auth_limiter (
  username      TEXT    NOT NULL,
  ip_hash       BYTEA   NOT NULL,
  fail_count    INT     NOT NULL DEFAULT 0,
  blocked_until TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (username, ip_hash)
);

CREATE INDEX IF NOT EXISTS auth_limiter_block_idx
  ON auth_limiter (blocked_until);

-- +goose Down
DROP TABLE IF EXISTS auth_limiter;

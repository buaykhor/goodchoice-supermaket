-- Run this once to set up the database schema
-- psql -d your_db_name -f schema.sql

CREATE TABLE IF NOT EXISTS users (
  id             SERIAL        PRIMARY KEY,
  fullname       VARCHAR(100)  NOT NULL,
  email          VARCHAR(255)  NOT NULL UNIQUE,
  password_hash  TEXT          NOT NULL,
  role           VARCHAR(20)   NOT NULL CHECK (role IN ('admin', 'staff', 'manager')),
  staff_id       VARCHAR(50)   DEFAULT NULL,
  is_active      BOOLEAN       NOT NULL DEFAULT TRUE,
  last_login_at  TIMESTAMPTZ   DEFAULT NULL,
  created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Index for fast email lookups on login
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (LOWER(email));

-- Auto-update updated_at on every row change
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

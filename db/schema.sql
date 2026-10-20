-- TrustVault schema. Idempotent: safe to run on every boot.
-- Works on PostgreSQL 14+ (Neon, Supabase, Render Postgres) and PGlite (tests/dev).

CREATE TABLE IF NOT EXISTS users (
  id            uuid PRIMARY KEY,
  email         text NOT NULL UNIQUE,
  name          text NOT NULL,
  role          text NOT NULL CHECK (role IN ('admin','owner','viewer')),
  password_hash text NOT NULL,
  active        boolean NOT NULL DEFAULT true,
  failed_logins integer NOT NULL DEFAULT 0,
  locked_until  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Server-side sessions. The cookie holds a random token; only its SHA-256 is stored.
-- Revoking a row (or deactivating the user) kills access on the very next request.
CREATE TABLE IF NOT EXISTS sessions (
  id_hash     text PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id),
  csrf_token  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  ip          text,
  user_agent  text
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS documents (
  id              uuid PRIMARY KEY,
  owner_id        uuid NOT NULL REFERENCES users(id),
  name            text NOT NULL,
  category        text NOT NULL DEFAULT 'general',
  description     text NOT NULL DEFAULT '',
  current_version integer NOT NULL DEFAULT 1,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  deleted_at      timestamptz,
  deleted_by      uuid REFERENCES users(id),
  purged_at       timestamptz
);
CREATE INDEX IF NOT EXISTS documents_owner_idx ON documents(owner_id);
CREATE INDEX IF NOT EXISTS documents_category_idx ON documents(lower(category));

-- Each version is encrypted with its own random data key (AES-256-GCM).
-- wrapped_key = iv(12) | tag(16) | DEK encrypted under the master key.
-- blob        = iv(12) | tag(16) | ciphertext.
-- Both are bound (GCM AAD) to "document id : version", so swapping blobs between rows fails.
CREATE TABLE IF NOT EXISTS document_versions (
  id          uuid PRIMARY KEY,
  document_id uuid NOT NULL REFERENCES documents(id),
  version     integer NOT NULL,
  filename    text NOT NULL,
  mime        text NOT NULL,
  size        integer NOT NULL,
  sha256      text NOT NULL,
  wrapped_key bytea,
  blob        bytea,
  uploaded_by uuid NOT NULL REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (document_id, version)
);

-- Per-document grants. History is kept: revoking sets revoked_at, it never deletes.
CREATE TABLE IF NOT EXISTS grants (
  id          uuid PRIMARY KEY,
  document_id uuid NOT NULL REFERENCES documents(id),
  user_id     uuid NOT NULL REFERENCES users(id),
  permission  text NOT NULL CHECK (permission IN ('read','edit')),
  granted_by  uuid NOT NULL REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  revoked_at  timestamptz,
  revoked_by  uuid REFERENCES users(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS grants_active_uq ON grants(document_id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS grants_user_idx ON grants(user_id) WHERE revoked_at IS NULL;

-- Suggestions made by the (rule-based) access advisor. A suggestion never grants anything.
CREATE TABLE IF NOT EXISTS ai_suggestions (
  id          uuid PRIMARY KEY,
  document_id uuid NOT NULL REFERENCES documents(id),
  owner_id    uuid NOT NULL REFERENCES users(id),
  payload     text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Audit trail: append-only, hash-chained with an HMAC key the database does not hold.
CREATE TABLE IF NOT EXISTS audit_log (
  seq            integer PRIMARY KEY,
  ts             text NOT NULL,
  actor_id       uuid,
  actor_email    text,
  action         text NOT NULL,
  outcome        text NOT NULL CHECK (outcome IN ('allowed','denied')),
  doc_id         uuid,
  target_user_id uuid,
  ip             text,
  detail         text NOT NULL,
  prev_hash      text NOT NULL,
  hash           text NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_doc_idx    ON audit_log(doc_id, seq);
CREATE INDEX IF NOT EXISTS audit_actor_idx  ON audit_log(actor_id, seq);
CREATE INDEX IF NOT EXISTS audit_action_idx ON audit_log(action, ts);
CREATE INDEX IF NOT EXISTS audit_ip_idx     ON audit_log(ip, action, ts);

-- Single row holding the current chain head; locked FOR UPDATE to serialise appends.
CREATE TABLE IF NOT EXISTS audit_head (
  id   integer PRIMARY KEY CHECK (id = 1),
  seq  integer NOT NULL,
  hash text NOT NULL
);
INSERT INTO audit_head(id, seq, hash)
VALUES (1, 0, '0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update ON audit_log;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

DROP TRIGGER IF EXISTS audit_no_truncate ON audit_log;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

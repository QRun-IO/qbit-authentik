-- Additive PostgreSQL migration for DESIGN sections 6.2 and 7.
-- Apply to the host's local database, NEVER Authentik's database.
-- Replace authentik_ with the configured table prefix when applicable.
-- Storage foundation only: MIRROR and WEBHOOK remain disabled until the
-- reconciler, durable processing, and session invalidation gates are complete.

CREATE TABLE authentik_user_mirror
(
   id SERIAL PRIMARY KEY,
   pk INTEGER NOT NULL UNIQUE,
   uuid VARCHAR(64),
   username VARCHAR(255) NOT NULL UNIQUE,
   email VARCHAR(255) UNIQUE,
   name VARCHAR(255),
   type VARCHAR(40),
   path VARCHAR(1024),
   source_is_superuser BOOLEAN,
   source_is_protected BOOLEAN,
   is_active BOOLEAN,
   last_login TIMESTAMP,
   is_superuser BOOLEAN,
   is_protected BOOLEAN,
   group_names TEXT,
   effective_permissions TEXT,
   mfa_device_count INTEGER,
   failed_logins24h INTEGER,
   refreshed_at TIMESTAMP NOT NULL
);
-- Blank email must be normalized to NULL. Ambiguous nonblank emails must
-- stop synchronization and cannot be used for permission fallback.
-- QQQ DATE_TIME binds UTC LocalDateTime values. Mirror DATE_TIME columns use
-- timezone-free TIMESTAMP containing UTC, so a non-UTC database session cannot
-- reinterpret them. JDBC-owned inbox/state clocks below use zoned instants.

CREATE TABLE authentik_group_mirror
(
   id SERIAL PRIMARY KEY,
   pk VARCHAR(64) NOT NULL UNIQUE,
   name VARCHAR(255),
   parent_pks TEXT,
   attributes TEXT,
   member_count INTEGER,
   is_superuser BOOLEAN,
   refreshed_at TIMESTAMP NOT NULL
);

CREATE TABLE authentik_membership_mirror
(
   id SERIAL PRIMARY KEY,
   user_pk INTEGER NOT NULL,
   group_pk VARCHAR(64) NOT NULL,
   group_name VARCHAR(255),
   refreshed_at TIMESTAMP NOT NULL,
   UNIQUE (user_pk, group_pk)
);
CREATE INDEX idx_authentik_membership_mirror_group ON authentik_membership_mirror (group_pk);

CREATE TABLE authentik_webhook_inbox
(
   id SERIAL PRIMARY KEY,
   event_pk VARCHAR(64) NOT NULL UNIQUE,
   payload_json TEXT NOT NULL,
   status VARCHAR(30) NOT NULL,
   attempts INTEGER NOT NULL DEFAULT 0,
   received_at TIMESTAMP WITH TIME ZONE NOT NULL,
   next_attempt_at TIMESTAMP WITH TIME ZONE,
   processed_at TIMESTAMP WITH TIME ZONE,
   lease_owner VARCHAR(64),
   lease_until TIMESTAMP WITH TIME ZONE,
   error_code VARCHAR(100)
);
CREATE INDEX idx_authentik_webhook_inbox_pending ON authentik_webhook_inbox (status, next_attempt_at);
CREATE INDEX idx_authentik_webhook_inbox_retention ON authentik_webhook_inbox (received_at);

CREATE TABLE authentik_sync_state
(
   id SERIAL PRIMARY KEY,
   sync_key VARCHAR(64) NOT NULL UNIQUE,
   watermark TIMESTAMP WITH TIME ZONE,
   last_full_sync TIMESTAMP WITH TIME ZONE,
   scope_fingerprint VARCHAR(64),
   lease_owner VARCHAR(64),
   lease_until TIMESTAMP WITH TIME ZONE
);

-- Authentication adapter-owned immutable identity binding. Store only the hash
-- of the QQQ session UUID, never its bearer credential or access/refresh tokens.
CREATE TABLE authentik_session_binding
(
   id SERIAL PRIMARY KEY,
   session_hash VARCHAR(64) NOT NULL UNIQUE,
   issuer_fingerprint VARCHAR(64) NOT NULL,
   user_pk INTEGER,
   user_uuid VARCHAR(64),
   user_reference VARCHAR(1024),
   expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
   revoked BOOLEAN NOT NULL DEFAULT FALSE,
   CHECK (revoked OR (user_pk IS NOT NULL AND user_pk > 0 AND user_uuid IS NOT NULL AND user_reference IS NOT NULL))
);
CREATE INDEX idx_authentik_session_binding_expiry ON authentik_session_binding (expires_at);

-- Internal, immutable invitation intent plus one-time binding/assignment progress.
-- Payload contains operator identity, reason and group IDs, never invitation URLs,
-- passwords, API tokens or email delivery credentials.
CREATE TABLE authentik_invitation_assignment
(
   id SERIAL PRIMARY KEY,
   reference VARCHAR(36) NOT NULL UNIQUE,
   scope_fingerprint VARCHAR(64) NOT NULL,
   invitation_id VARCHAR(36) UNIQUE,
   status VARCHAR(20) NOT NULL,
   payload_json TEXT NOT NULL,
   created_at TIMESTAMP WITH TIME ZONE NOT NULL,
   expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
   CHECK (status IN ('WAITING', 'READY', 'COMPLETE', 'REVIEW', 'CANCELLED'))
);
CREATE INDEX idx_authentik_invitation_assignment_expiry ON authentik_invitation_assignment (expires_at);

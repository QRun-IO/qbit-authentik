-- The qbit's own tables (DESIGN.md section 6.2) for the host's local RDBMS backend.
-- Column names are the snake_case of the QQQ field names. PostgreSQL syntax; adapt the
-- types for another database. The tables are written only by the qbit (the generic
-- insert, update and delete capabilities are off); authentik_admin_action is append-only
-- in practice (rows move from RUNNING to a final status, and are never deleted).
-- Retention: the audit trail is kept 2 years (DESIGN.md section 9.4).

CREATE TABLE authentik_admin_action
(
   id                  SERIAL PRIMARY KEY,
   create_date         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
   modify_date         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
   correlation_id      VARCHAR(64),
   action_name         VARCHAR(60)  NOT NULL,
   operator            VARCHAR(255),
   reason              TEXT,
   target_type         VARCHAR(30),
   target_key          VARCHAR(100),
   target_label        VARCHAR(255),
   before_text         TEXT,
   after_text          TEXT,
   status              VARCHAR(30)  NOT NULL,
   error_message       TEXT,
   authentik_event_pk  VARCHAR(64),
   approver            VARCHAR(255)
);

CREATE INDEX idx_authentik_admin_action_create_date ON authentik_admin_action (create_date);
CREATE INDEX idx_authentik_admin_action_target ON authentik_admin_action (target_type, target_key);
CREATE INDEX idx_authentik_admin_action_operator ON authentik_admin_action (operator);

CREATE TABLE authentik_approval_request
(
   id            SERIAL PRIMARY KEY,
   create_date   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
   modify_date   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
   action_name   VARCHAR(60)  NOT NULL,
   target_key    VARCHAR(100),
   target_label  VARCHAR(255),
   summary       TEXT,
   reason        TEXT,
   payload_json  TEXT         NOT NULL,
   requester     VARCHAR(255) NOT NULL,
   approver      VARCHAR(255),
   status        VARCHAR(30)  NOT NULL,
   expires_date  TIMESTAMP WITH TIME ZONE,
   decided_date  TIMESTAMP WITH TIME ZONE,
   error_message TEXT
);

CREATE INDEX idx_authentik_approval_request_status ON authentik_approval_request (status);

package operation

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/sqlitedb"
)

// SQLiteStore is the durable Store of ADR-003 on the approved SQLite driver (D1). It implements AuditedStore.
//
// Properties enforced by the schema itself rather than by caller discipline:
//   - (project_id, idempotency_key) is unique, so an idempotency key survives a restart and a concurrent replay
//     resolves to one row;
//   - Update is a compare-and-swap on generation in a single statement;
//   - a terminal operation (succeeded, failed, cancelled) cannot be modified, and identity fields never change
//     (triggers abort the statement);
//   - an audit event is inserted in the same transaction as the state change it records.
//
// All failures are reported as the typed category "internal" (or "conflict" for a lost CAS / terminal record);
// driver errors, SQL text and file paths never leave this package. Secrets are never stored: the schema has no free
// text column other than the closed-vocabulary error_category.
type SQLiteStore struct {
	db *sql.DB
}

// schema is append-only (sqlitedb.Migrate); a published step is never edited.
var schema = []string{`
CREATE TABLE operations (
	seq             INTEGER PRIMARY KEY AUTOINCREMENT,
	id              TEXT NOT NULL UNIQUE,
	project_id      TEXT NOT NULL,
	resource_kind   TEXT NOT NULL CHECK (resource_kind = 'VM'),
	resource_id     TEXT NOT NULL,
	type            TEXT NOT NULL CHECK (type IN ('create','start','stop','delete')),
	status          TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed','retryable_failure','cancelled')),
	idempotency_key TEXT NOT NULL,
	requested_by    TEXT NOT NULL,
	generation      INTEGER NOT NULL CHECK (generation >= 1),
	attempts        INTEGER NOT NULL CHECK (attempts >= 0),
	error_category  TEXT NOT NULL DEFAULT '' CHECK (error_category IN
		('','validation','forbidden','not_found','conflict','unavailable','timeout','host_error','internal')),
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	UNIQUE (project_id, idempotency_key)
);
CREATE INDEX operations_open ON operations (status, seq) WHERE status IN ('pending','running','retryable_failure');
CREATE TRIGGER operations_terminal_immutable BEFORE UPDATE ON operations
WHEN OLD.status IN ('succeeded','failed','cancelled')
BEGIN SELECT RAISE(ABORT, 'operation is terminal'); END;
CREATE TRIGGER operations_identity_immutable BEFORE UPDATE ON operations
WHEN NEW.id <> OLD.id OR NEW.seq <> OLD.seq OR NEW.project_id <> OLD.project_id OR NEW.resource_kind <> OLD.resource_kind
  OR NEW.resource_id <> OLD.resource_id OR NEW.type <> OLD.type OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at OR NEW.attempts < OLD.attempts
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;
CREATE TABLE operation_audit (
	seq            INTEGER PRIMARY KEY AUTOINCREMENT,
	at             INTEGER NOT NULL,
	operation_id   TEXT NOT NULL REFERENCES operations (id),
	project_id     TEXT NOT NULL,
	actor          TEXT NOT NULL,
	event          TEXT NOT NULL,
	outcome        TEXT NOT NULL,
	error_category TEXT NOT NULL DEFAULT ''
);
CREATE TRIGGER operation_audit_append_only BEFORE UPDATE ON operation_audit
BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER operation_audit_no_delete BEFORE DELETE ON operation_audit
BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;`, `
ALTER TABLE operations ADD COLUMN vcpus INTEGER NOT NULL DEFAULT 0 CHECK (vcpus BETWEEN 0 AND 64);
ALTER TABLE operations ADD COLUMN memory_mib INTEGER NOT NULL DEFAULT 0 CHECK (memory_mib = 0 OR memory_mib BETWEEN 64 AND 1048576);
DROP TRIGGER operations_identity_immutable;
CREATE TRIGGER operations_identity_immutable BEFORE UPDATE ON operations
WHEN NEW.id <> OLD.id OR NEW.seq <> OLD.seq OR NEW.project_id <> OLD.project_id OR NEW.resource_kind <> OLD.resource_kind
  OR NEW.resource_id <> OLD.resource_id OR NEW.type <> OLD.type OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at OR NEW.attempts < OLD.attempts
  OR NEW.vcpus <> OLD.vcpus OR NEW.memory_mib <> OLD.memory_mib
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;`, `
ALTER TABLE operations ADD COLUMN unknown_outcome INTEGER NOT NULL DEFAULT 0 CHECK (unknown_outcome IN (0, 1));
CREATE TRIGGER operations_unknown_monotonic BEFORE UPDATE ON operations WHEN NEW.unknown_outcome < OLD.unknown_outcome
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;`, `
ALTER TABLE operations ADD COLUMN spec_uuid TEXT NOT NULL DEFAULT '' CHECK (length(spec_uuid) <= 36);
ALTER TABLE operations ADD COLUMN spec_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_fingerprint) <= 64);
ALTER TABLE operations ADD COLUMN spec_image_id TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_id) <= 63);
ALTER TABLE operations ADD COLUMN spec_image_sha256 TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_sha256) <= 64);
ALTER TABLE operations ADD COLUMN spec_disk_gib INTEGER NOT NULL DEFAULT 0 CHECK (spec_disk_gib BETWEEN 0 AND 4096);
ALTER TABLE operations ADD COLUMN spec_ssh_key TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_key) <= 2048);
ALTER TABLE operations ADD COLUMN spec_ssh_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_fingerprint) <= 64);
ALTER TABLE operations ADD COLUMN spec_network TEXT NOT NULL DEFAULT '' CHECK (length(spec_network) <= 63);
DROP TRIGGER operations_identity_immutable;
CREATE TRIGGER operations_identity_immutable BEFORE UPDATE ON operations
WHEN NEW.id <> OLD.id OR NEW.seq <> OLD.seq OR NEW.project_id <> OLD.project_id OR NEW.resource_kind <> OLD.resource_kind
  OR NEW.resource_id <> OLD.resource_id OR NEW.type <> OLD.type OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at OR NEW.attempts < OLD.attempts
  OR NEW.vcpus <> OLD.vcpus OR NEW.memory_mib <> OLD.memory_mib
  OR NEW.spec_uuid <> OLD.spec_uuid OR NEW.spec_fingerprint <> OLD.spec_fingerprint OR NEW.spec_image_id <> OLD.spec_image_id
  OR NEW.spec_image_sha256 <> OLD.spec_image_sha256 OR NEW.spec_disk_gib <> OLD.spec_disk_gib OR NEW.spec_ssh_key <> OLD.spec_ssh_key
  OR NEW.spec_ssh_fingerprint <> OLD.spec_ssh_fingerprint OR NEW.spec_network <> OLD.spec_network
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;`, `
PRAGMA defer_foreign_keys = ON;
CREATE TABLE operations_new (
	seq             INTEGER PRIMARY KEY AUTOINCREMENT,
	id              TEXT NOT NULL UNIQUE,
	project_id      TEXT NOT NULL,
	resource_kind   TEXT NOT NULL CHECK (resource_kind = 'VM'),
	resource_id     TEXT NOT NULL,
	type            TEXT NOT NULL CHECK (type IN ('create','start','stop','reboot','force_off','delete')),
	status          TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed','retryable_failure','cancelled')),
	idempotency_key TEXT NOT NULL,
	requested_by    TEXT NOT NULL,
	generation      INTEGER NOT NULL CHECK (generation >= 1),
	attempts        INTEGER NOT NULL CHECK (attempts >= 0),
	error_category  TEXT NOT NULL DEFAULT '' CHECK (error_category IN
		('','validation','forbidden','not_found','conflict','unavailable','timeout','host_error','internal')),
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	vcpus INTEGER NOT NULL DEFAULT 0 CHECK (vcpus BETWEEN 0 AND 64),
	memory_mib INTEGER NOT NULL DEFAULT 0 CHECK (memory_mib = 0 OR memory_mib BETWEEN 64 AND 1048576),
	unknown_outcome INTEGER NOT NULL DEFAULT 0 CHECK (unknown_outcome IN (0, 1)),
	spec_uuid TEXT NOT NULL DEFAULT '' CHECK (length(spec_uuid) <= 36),
	spec_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_fingerprint) <= 64),
	spec_image_id TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_id) <= 63),
	spec_image_sha256 TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_sha256) <= 64),
	spec_disk_gib INTEGER NOT NULL DEFAULT 0 CHECK (spec_disk_gib BETWEEN 0 AND 4096),
	spec_ssh_key TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_key) <= 2048),
	spec_ssh_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_fingerprint) <= 64),
	spec_network TEXT NOT NULL DEFAULT '' CHECK (length(spec_network) <= 63),
	UNIQUE (project_id, idempotency_key)
);
INSERT INTO operations_new (seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network)
SELECT seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network FROM operations;
DROP TABLE operations;
ALTER TABLE operations_new RENAME TO operations;
CREATE INDEX operations_open ON operations (status, seq) WHERE status IN ('pending','running','retryable_failure');
CREATE TRIGGER operations_terminal_immutable BEFORE UPDATE ON operations
WHEN OLD.status IN ('succeeded','failed','cancelled')
BEGIN SELECT RAISE(ABORT, 'operation is terminal'); END;
CREATE TRIGGER operations_unknown_monotonic BEFORE UPDATE ON operations WHEN NEW.unknown_outcome < OLD.unknown_outcome
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;
CREATE TRIGGER operations_identity_immutable BEFORE UPDATE ON operations
WHEN NEW.id <> OLD.id OR NEW.seq <> OLD.seq OR NEW.project_id <> OLD.project_id OR NEW.resource_kind <> OLD.resource_kind
  OR NEW.resource_id <> OLD.resource_id OR NEW.type <> OLD.type OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at OR NEW.attempts < OLD.attempts
  OR NEW.vcpus <> OLD.vcpus OR NEW.memory_mib <> OLD.memory_mib
  OR NEW.spec_uuid <> OLD.spec_uuid OR NEW.spec_fingerprint <> OLD.spec_fingerprint OR NEW.spec_image_id <> OLD.spec_image_id
  OR NEW.spec_image_sha256 <> OLD.spec_image_sha256 OR NEW.spec_disk_gib <> OLD.spec_disk_gib OR NEW.spec_ssh_key <> OLD.spec_ssh_key
  OR NEW.spec_ssh_fingerprint <> OLD.spec_ssh_fingerprint OR NEW.spec_network <> OLD.spec_network
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;`, `
PRAGMA defer_foreign_keys = ON;
CREATE TABLE operations_new (
	seq             INTEGER PRIMARY KEY AUTOINCREMENT,
	id              TEXT NOT NULL UNIQUE,
	project_id      TEXT NOT NULL,
	resource_kind   TEXT NOT NULL CHECK (resource_kind IN ('VM','Backup')),
	resource_id     TEXT NOT NULL,
	type            TEXT NOT NULL CHECK (type IN ('create','start','stop','reboot','force_off','delete','resize','reinstall','snapshot','restore_snapshot','delete_snapshot','backup','restore')),
	status          TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed','retryable_failure','cancelled')),
	idempotency_key TEXT NOT NULL,
	requested_by    TEXT NOT NULL,
	generation      INTEGER NOT NULL CHECK (generation >= 1),
	attempts        INTEGER NOT NULL CHECK (attempts >= 0),
	error_category  TEXT NOT NULL DEFAULT '' CHECK (error_category IN
		('','validation','forbidden','not_found','conflict','unavailable','timeout','host_error','internal')),
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	vcpus INTEGER NOT NULL DEFAULT 0 CHECK (vcpus BETWEEN 0 AND 64),
	memory_mib INTEGER NOT NULL DEFAULT 0 CHECK (memory_mib = 0 OR memory_mib BETWEEN 64 AND 1048576),
	unknown_outcome INTEGER NOT NULL DEFAULT 0 CHECK (unknown_outcome IN (0, 1)),
	spec_uuid TEXT NOT NULL DEFAULT '' CHECK (length(spec_uuid) <= 36),
	spec_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_fingerprint) <= 64),
	spec_image_id TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_id) <= 63),
	spec_image_sha256 TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_sha256) <= 64),
	spec_disk_gib INTEGER NOT NULL DEFAULT 0 CHECK (spec_disk_gib BETWEEN 0 AND 4096),
	spec_ssh_key TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_key) <= 2048),
	spec_ssh_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_fingerprint) <= 64),
	spec_network TEXT NOT NULL DEFAULT '' CHECK (length(spec_network) <= 63),
	params TEXT NOT NULL DEFAULT '' CHECK (length(params) <= 4096),
	UNIQUE (project_id, idempotency_key)
);
INSERT INTO operations_new (seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params)
SELECT seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, '' FROM operations;
DROP TABLE operations;
ALTER TABLE operations_new RENAME TO operations;
CREATE INDEX operations_open ON operations (status, seq) WHERE status IN ('pending','running','retryable_failure');
CREATE TRIGGER operations_terminal_immutable BEFORE UPDATE ON operations
WHEN OLD.status IN ('succeeded','failed','cancelled')
BEGIN SELECT RAISE(ABORT, 'operation is terminal'); END;
CREATE TRIGGER operations_unknown_monotonic BEFORE UPDATE ON operations WHEN NEW.unknown_outcome < OLD.unknown_outcome
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;
CREATE TRIGGER operations_identity_immutable BEFORE UPDATE ON operations
WHEN NEW.id <> OLD.id OR NEW.seq <> OLD.seq OR NEW.project_id <> OLD.project_id OR NEW.resource_kind <> OLD.resource_kind
  OR NEW.resource_id <> OLD.resource_id OR NEW.type <> OLD.type OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at OR NEW.attempts < OLD.attempts
  OR NEW.vcpus <> OLD.vcpus OR NEW.memory_mib <> OLD.memory_mib
  OR NEW.spec_uuid <> OLD.spec_uuid OR NEW.spec_fingerprint <> OLD.spec_fingerprint OR NEW.spec_image_id <> OLD.spec_image_id
  OR NEW.spec_image_sha256 <> OLD.spec_image_sha256 OR NEW.spec_disk_gib <> OLD.spec_disk_gib OR NEW.spec_ssh_key <> OLD.spec_ssh_key
  OR NEW.spec_ssh_fingerprint <> OLD.spec_ssh_fingerprint OR NEW.spec_network <> OLD.spec_network OR NEW.params <> OLD.params
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;`, `
PRAGMA defer_foreign_keys = ON;
CREATE TABLE operations_new (
	seq             INTEGER PRIMARY KEY AUTOINCREMENT,
	id              TEXT NOT NULL UNIQUE,
	project_id      TEXT NOT NULL,
	resource_kind   TEXT NOT NULL CHECK (resource_kind IN ('VM','Backup','VirtualNetwork')),
	resource_id     TEXT NOT NULL,
	type            TEXT NOT NULL CHECK (type IN ('create','start','stop','reboot','force_off','delete','resize','reinstall','snapshot','restore_snapshot','delete_snapshot','backup','restore','network_create','network_start','network_stop','network_autostart','network_delete','compute','reserve_ip','release_ip')),
	status          TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed','retryable_failure','cancelled')),
	idempotency_key TEXT NOT NULL,
	requested_by    TEXT NOT NULL,
	generation      INTEGER NOT NULL CHECK (generation >= 1),
	attempts        INTEGER NOT NULL CHECK (attempts >= 0),
	error_category  TEXT NOT NULL DEFAULT '' CHECK (error_category IN
		('','validation','forbidden','not_found','conflict','unavailable','timeout','host_error','internal')),
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	vcpus INTEGER NOT NULL DEFAULT 0 CHECK (vcpus BETWEEN 0 AND 64),
	memory_mib INTEGER NOT NULL DEFAULT 0 CHECK (memory_mib = 0 OR memory_mib BETWEEN 64 AND 1048576),
	unknown_outcome INTEGER NOT NULL DEFAULT 0 CHECK (unknown_outcome IN (0, 1)),
	spec_uuid TEXT NOT NULL DEFAULT '' CHECK (length(spec_uuid) <= 36),
	spec_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_fingerprint) <= 64),
	spec_image_id TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_id) <= 63),
	spec_image_sha256 TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_sha256) <= 64),
	spec_disk_gib INTEGER NOT NULL DEFAULT 0 CHECK (spec_disk_gib BETWEEN 0 AND 4096),
	spec_ssh_key TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_key) <= 2048),
	spec_ssh_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_fingerprint) <= 64),
	spec_network TEXT NOT NULL DEFAULT '' CHECK (length(spec_network) <= 63),
	params TEXT NOT NULL DEFAULT '' CHECK (length(params) <= 4096),
	UNIQUE (project_id, idempotency_key)
);
INSERT INTO operations_new (seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params)
SELECT seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params FROM operations;
DROP TABLE operations;
ALTER TABLE operations_new RENAME TO operations;
CREATE INDEX operations_open ON operations (status, seq) WHERE status IN ('pending','running','retryable_failure');
CREATE TRIGGER operations_terminal_immutable BEFORE UPDATE ON operations
WHEN OLD.status IN ('succeeded','failed','cancelled')
BEGIN SELECT RAISE(ABORT, 'operation is terminal'); END;
CREATE TRIGGER operations_unknown_monotonic BEFORE UPDATE ON operations WHEN NEW.unknown_outcome < OLD.unknown_outcome
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;
CREATE TRIGGER operations_identity_immutable BEFORE UPDATE ON operations
WHEN NEW.id <> OLD.id OR NEW.seq <> OLD.seq OR NEW.project_id <> OLD.project_id OR NEW.resource_kind <> OLD.resource_kind
  OR NEW.resource_id <> OLD.resource_id OR NEW.type <> OLD.type OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at OR NEW.attempts < OLD.attempts
  OR NEW.vcpus <> OLD.vcpus OR NEW.memory_mib <> OLD.memory_mib
  OR NEW.spec_uuid <> OLD.spec_uuid OR NEW.spec_fingerprint <> OLD.spec_fingerprint OR NEW.spec_image_id <> OLD.spec_image_id
  OR NEW.spec_image_sha256 <> OLD.spec_image_sha256 OR NEW.spec_disk_gib <> OLD.spec_disk_gib OR NEW.spec_ssh_key <> OLD.spec_ssh_key
  OR NEW.spec_ssh_fingerprint <> OLD.spec_ssh_fingerprint OR NEW.spec_network <> OLD.spec_network OR NEW.params <> OLD.params
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;`, `
-- sqlitedb:foreign-keys-off
PRAGMA defer_foreign_keys = ON;
CREATE TABLE operations_new (
	seq             INTEGER PRIMARY KEY AUTOINCREMENT,
	id              TEXT NOT NULL UNIQUE,
	project_id      TEXT NOT NULL,
	resource_kind   TEXT NOT NULL CHECK (resource_kind IN ('VM','Backup','VirtualNetwork','Volume')),
	resource_id     TEXT NOT NULL,
	type            TEXT NOT NULL CHECK (type IN ('create','start','stop','reboot','force_off','delete','resize','reinstall','snapshot','restore_snapshot','delete_snapshot','backup','restore','network_create','network_start','network_stop','network_autostart','network_delete','compute','reserve_ip','release_ip','volume_create','volume_attach','volume_detach','volume_delete','eject_iso','backup_export')),
	status          TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed','retryable_failure','cancelled')),
	idempotency_key TEXT NOT NULL,
	requested_by    TEXT NOT NULL,
	generation      INTEGER NOT NULL CHECK (generation >= 1),
	attempts        INTEGER NOT NULL CHECK (attempts >= 0),
	error_category  TEXT NOT NULL DEFAULT '' CHECK (error_category IN
		('','validation','forbidden','not_found','conflict','unavailable','timeout','host_error','internal')),
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	vcpus INTEGER NOT NULL DEFAULT 0 CHECK (vcpus BETWEEN 0 AND 64),
	memory_mib INTEGER NOT NULL DEFAULT 0 CHECK (memory_mib = 0 OR memory_mib BETWEEN 64 AND 1048576),
	unknown_outcome INTEGER NOT NULL DEFAULT 0 CHECK (unknown_outcome IN (0, 1)),
	spec_uuid TEXT NOT NULL DEFAULT '' CHECK (length(spec_uuid) <= 36),
	spec_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_fingerprint) <= 64),
	spec_image_id TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_id) <= 63),
	spec_image_sha256 TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_sha256) <= 64),
	spec_disk_gib INTEGER NOT NULL DEFAULT 0 CHECK (spec_disk_gib BETWEEN 0 AND 4096),
	spec_ssh_key TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_key) <= 2048),
	spec_ssh_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_fingerprint) <= 64),
	spec_network TEXT NOT NULL DEFAULT '' CHECK (length(spec_network) <= 63),
	params TEXT NOT NULL DEFAULT '' CHECK (length(params) <= 4096),
	UNIQUE (project_id, idempotency_key)
);
INSERT INTO operations_new (seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params)
SELECT seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params FROM operations;
DROP TABLE operations;
ALTER TABLE operations_new RENAME TO operations;
CREATE INDEX operations_open ON operations (status, seq) WHERE status IN ('pending','running','retryable_failure');
CREATE TRIGGER operations_terminal_immutable BEFORE UPDATE ON operations
WHEN OLD.status IN ('succeeded','failed','cancelled')
BEGIN SELECT RAISE(ABORT, 'operation is terminal'); END;
CREATE TRIGGER operations_unknown_monotonic BEFORE UPDATE ON operations WHEN NEW.unknown_outcome < OLD.unknown_outcome
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;
CREATE TRIGGER operations_identity_immutable BEFORE UPDATE ON operations
WHEN NEW.id <> OLD.id OR NEW.seq <> OLD.seq OR NEW.project_id <> OLD.project_id OR NEW.resource_kind <> OLD.resource_kind
  OR NEW.resource_id <> OLD.resource_id OR NEW.type <> OLD.type OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at OR NEW.attempts < OLD.attempts
  OR NEW.vcpus <> OLD.vcpus OR NEW.memory_mib <> OLD.memory_mib
  OR NEW.spec_uuid <> OLD.spec_uuid OR NEW.spec_fingerprint <> OLD.spec_fingerprint OR NEW.spec_image_id <> OLD.spec_image_id
  OR NEW.spec_image_sha256 <> OLD.spec_image_sha256 OR NEW.spec_disk_gib <> OLD.spec_disk_gib OR NEW.spec_ssh_key <> OLD.spec_ssh_key
  OR NEW.spec_ssh_fingerprint <> OLD.spec_ssh_fingerprint OR NEW.spec_network <> OLD.spec_network OR NEW.params <> OLD.params
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;`, `
-- sqlitedb:foreign-keys-off
PRAGMA defer_foreign_keys = ON;
CREATE TABLE operations_new (
	seq             INTEGER PRIMARY KEY AUTOINCREMENT,
	id              TEXT NOT NULL UNIQUE,
	project_id      TEXT NOT NULL,
	resource_kind   TEXT NOT NULL CHECK (resource_kind IN ('VM','Backup','VirtualNetwork','Volume','Event')),
	resource_id     TEXT NOT NULL,
	type            TEXT NOT NULL CHECK (type IN ('create','start','stop','reboot','force_off','delete','resize','reinstall','snapshot','restore_snapshot','delete_snapshot','backup','restore','network_create','network_start','network_stop','network_autostart','network_delete','compute','reserve_ip','release_ip','volume_create','volume_attach','volume_detach','volume_delete','eject_iso','backup_export','alert_acknowledge','schedule_set','schedule_clear')),
	status          TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed','retryable_failure','cancelled')),
	idempotency_key TEXT NOT NULL,
	requested_by    TEXT NOT NULL,
	generation      INTEGER NOT NULL CHECK (generation >= 1),
	attempts        INTEGER NOT NULL CHECK (attempts >= 0),
	error_category  TEXT NOT NULL DEFAULT '' CHECK (error_category IN
		('','validation','forbidden','not_found','conflict','unavailable','timeout','host_error','internal')),
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	vcpus INTEGER NOT NULL DEFAULT 0 CHECK (vcpus BETWEEN 0 AND 64),
	memory_mib INTEGER NOT NULL DEFAULT 0 CHECK (memory_mib = 0 OR memory_mib BETWEEN 64 AND 1048576),
	unknown_outcome INTEGER NOT NULL DEFAULT 0 CHECK (unknown_outcome IN (0, 1)),
	spec_uuid TEXT NOT NULL DEFAULT '' CHECK (length(spec_uuid) <= 36),
	spec_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_fingerprint) <= 64),
	spec_image_id TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_id) <= 63),
	spec_image_sha256 TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_sha256) <= 64),
	spec_disk_gib INTEGER NOT NULL DEFAULT 0 CHECK (spec_disk_gib BETWEEN 0 AND 4096),
	spec_ssh_key TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_key) <= 2048),
	spec_ssh_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_fingerprint) <= 64),
	spec_network TEXT NOT NULL DEFAULT '' CHECK (length(spec_network) <= 63),
	params TEXT NOT NULL DEFAULT '' CHECK (length(params) <= 4096),
	UNIQUE (project_id, idempotency_key)
);
INSERT INTO operations_new (seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params)
SELECT seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params FROM operations;
DROP TABLE operations;
ALTER TABLE operations_new RENAME TO operations;
CREATE INDEX operations_open ON operations (status, seq) WHERE status IN ('pending','running','retryable_failure');
CREATE TRIGGER operations_terminal_immutable BEFORE UPDATE ON operations
WHEN OLD.status IN ('succeeded','failed','cancelled')
BEGIN SELECT RAISE(ABORT, 'operation is terminal'); END;
CREATE TRIGGER operations_unknown_monotonic BEFORE UPDATE ON operations WHEN NEW.unknown_outcome < OLD.unknown_outcome
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;
CREATE TRIGGER operations_identity_immutable BEFORE UPDATE ON operations
WHEN NEW.id <> OLD.id OR NEW.seq <> OLD.seq OR NEW.project_id <> OLD.project_id OR NEW.resource_kind <> OLD.resource_kind
  OR NEW.resource_id <> OLD.resource_id OR NEW.type <> OLD.type OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at OR NEW.attempts < OLD.attempts
  OR NEW.vcpus <> OLD.vcpus OR NEW.memory_mib <> OLD.memory_mib
  OR NEW.spec_uuid <> OLD.spec_uuid OR NEW.spec_fingerprint <> OLD.spec_fingerprint OR NEW.spec_image_id <> OLD.spec_image_id
  OR NEW.spec_image_sha256 <> OLD.spec_image_sha256 OR NEW.spec_disk_gib <> OLD.spec_disk_gib OR NEW.spec_ssh_key <> OLD.spec_ssh_key
  OR NEW.spec_ssh_fingerprint <> OLD.spec_ssh_fingerprint OR NEW.spec_network <> OLD.spec_network OR NEW.params <> OLD.params
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;`, `
-- sqlitedb:foreign-keys-off
PRAGMA defer_foreign_keys = ON;
CREATE TABLE operations_new (
	seq             INTEGER PRIMARY KEY AUTOINCREMENT,
	id              TEXT NOT NULL UNIQUE,
	project_id      TEXT NOT NULL,
	resource_kind   TEXT NOT NULL CHECK (resource_kind IN ('VM','Backup','VirtualNetwork','Volume','Event')),
	resource_id     TEXT NOT NULL,
	type            TEXT NOT NULL CHECK (type IN ('create','start','stop','reboot','force_off','delete','resize','reinstall','snapshot','restore_snapshot','delete_snapshot','backup','restore','network_create','network_start','network_stop','network_autostart','network_delete','compute','reserve_ip','release_ip','volume_create','volume_attach','volume_detach','volume_delete','eject_iso','backup_export','alert_acknowledge','schedule_set','schedule_clear','graphics_enable','iso_attach','rescue','unrescue')),
	status          TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed','retryable_failure','cancelled')),
	idempotency_key TEXT NOT NULL,
	requested_by    TEXT NOT NULL,
	generation      INTEGER NOT NULL CHECK (generation >= 1),
	attempts        INTEGER NOT NULL CHECK (attempts >= 0),
	error_category  TEXT NOT NULL DEFAULT '' CHECK (error_category IN
		('','validation','forbidden','not_found','conflict','unavailable','timeout','host_error','internal')),
	created_at      INTEGER NOT NULL,
	updated_at      INTEGER NOT NULL,
	vcpus INTEGER NOT NULL DEFAULT 0 CHECK (vcpus BETWEEN 0 AND 64),
	memory_mib INTEGER NOT NULL DEFAULT 0 CHECK (memory_mib = 0 OR memory_mib BETWEEN 64 AND 1048576),
	unknown_outcome INTEGER NOT NULL DEFAULT 0 CHECK (unknown_outcome IN (0, 1)),
	spec_uuid TEXT NOT NULL DEFAULT '' CHECK (length(spec_uuid) <= 36),
	spec_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_fingerprint) <= 64),
	spec_image_id TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_id) <= 63),
	spec_image_sha256 TEXT NOT NULL DEFAULT '' CHECK (length(spec_image_sha256) <= 64),
	spec_disk_gib INTEGER NOT NULL DEFAULT 0 CHECK (spec_disk_gib BETWEEN 0 AND 4096),
	spec_ssh_key TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_key) <= 2048),
	spec_ssh_fingerprint TEXT NOT NULL DEFAULT '' CHECK (length(spec_ssh_fingerprint) <= 64),
	spec_network TEXT NOT NULL DEFAULT '' CHECK (length(spec_network) <= 63),
	params TEXT NOT NULL DEFAULT '' CHECK (length(params) <= 4096),
	UNIQUE (project_id, idempotency_key)
);
INSERT INTO operations_new (seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params)
SELECT seq, id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by, generation, attempts,
	error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome, spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256,
	spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params FROM operations;
DROP TABLE operations;
ALTER TABLE operations_new RENAME TO operations;
CREATE INDEX operations_open ON operations (status, seq) WHERE status IN ('pending','running','retryable_failure');
CREATE TRIGGER operations_terminal_immutable BEFORE UPDATE ON operations
WHEN OLD.status IN ('succeeded','failed','cancelled')
BEGIN SELECT RAISE(ABORT, 'operation is terminal'); END;
CREATE TRIGGER operations_unknown_monotonic BEFORE UPDATE ON operations WHEN NEW.unknown_outcome < OLD.unknown_outcome
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;
CREATE TRIGGER operations_identity_immutable BEFORE UPDATE ON operations
WHEN NEW.id <> OLD.id OR NEW.seq <> OLD.seq OR NEW.project_id <> OLD.project_id OR NEW.resource_kind <> OLD.resource_kind
  OR NEW.resource_id <> OLD.resource_id OR NEW.type <> OLD.type OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at OR NEW.attempts < OLD.attempts
  OR NEW.vcpus <> OLD.vcpus OR NEW.memory_mib <> OLD.memory_mib
  OR NEW.spec_uuid <> OLD.spec_uuid OR NEW.spec_fingerprint <> OLD.spec_fingerprint OR NEW.spec_image_id <> OLD.spec_image_id
  OR NEW.spec_image_sha256 <> OLD.spec_image_sha256 OR NEW.spec_disk_gib <> OLD.spec_disk_gib OR NEW.spec_ssh_key <> OLD.spec_ssh_key
  OR NEW.spec_ssh_fingerprint <> OLD.spec_ssh_fingerprint OR NEW.spec_network <> OLD.spec_network OR NEW.params <> OLD.params
BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;`}

// SchemaVersion is the schema version this build migrates the operation tables to.
func SchemaVersion() int { return len(schema) }

// OpenSQLite migrates the schema in db and returns a store over it. The caller owns db.
func OpenSQLite(ctx context.Context, db *sql.DB) (*SQLiteStore, error) {
	if err := sqlitedb.Migrate(ctx, db, "operation", schema); err != nil {
		return nil, fail(CatInternal)
	}
	return &SQLiteStore{db: db}, nil
}

const columns = `id, project_id, resource_kind, resource_id, type, status, idempotency_key, requested_by,
	generation, attempts, error_category, created_at, updated_at, vcpus, memory_mib, unknown_outcome,
	spec_uuid, spec_fingerprint, spec_image_id, spec_image_sha256, spec_disk_gib, spec_ssh_key, spec_ssh_fingerprint, spec_network, params`

type scanner interface{ Scan(...any) error }

func scan(r scanner) (Operation, error) {
	var (
		op                 Operation
		typ, status        string
		created, updatedAt int64
		unknown            int
		params             string
	)
	if err := r.Scan(&op.ID, &op.ProjectID, &op.ResourceKind, &op.ResourceID, &typ, &status, &op.IdempotencyKey,
		&op.RequestedBy, &op.Generation, &op.Attempts, &op.ErrorCategory, &created, &updatedAt, &op.Spec.VCPUs, &op.Spec.MemoryMiB, &unknown,
		&op.Spec.UUID, &op.Spec.Fingerprint, &op.Spec.ImageID, &op.Spec.ImageSHA256, &op.Spec.DiskGiB, &op.Spec.SSHPublicKey,
		&op.Spec.SSHFingerprint, &op.Spec.Network, &params); err != nil {
		return Operation{}, err
	}
	p, perr := UnmarshalParams(params)
	if perr != nil {
		return Operation{}, perr
	}
	op.Params = p
	op.Type, op.Status = Type(typ), Status(status)
	op.UnknownOutcome = unknown == 1
	op.CreatedAt, op.UpdatedAt = time.Unix(0, created).UTC(), time.Unix(0, updatedAt).UTC()
	return op, nil
}

func internal(error) error { return fail(CatInternal) }

func insertAudit(ctx context.Context, tx *sql.Tx, ev AuditEvent) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO operation_audit (at, operation_id, project_id, actor, event, outcome, error_category)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, ev.At.UnixNano(), ev.OperationID, ev.ProjectID, ev.Actor, ev.Event, ev.Outcome, ev.ErrorCategory)
	return err
}

// Insert implements Store.
func (s *SQLiteStore) Insert(op Operation) (Operation, bool, error) { return s.insert(op, nil) }

// InsertAudited implements AuditedStore. The event is stored only when the operation is created.
func (s *SQLiteStore) InsertAudited(op Operation, ev AuditEvent) (Operation, bool, error) {
	return s.insert(op, &ev)
}

func (s *SQLiteStore) insert(op Operation, ev *AuditEvent) (Operation, bool, error) {
	ctx := context.Background()
	params, perr := MarshalParams(op.Params)
	if perr != nil {
		return Operation{}, false, internal(perr)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, false, internal(err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO operations (`+columns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (project_id, idempotency_key) DO NOTHING`,
		op.ID, op.ProjectID, op.ResourceKind, op.ResourceID, string(op.Type), string(op.Status), op.IdempotencyKey,
		op.RequestedBy, op.Generation, op.Attempts, op.ErrorCategory, op.CreatedAt.UnixNano(), op.UpdatedAt.UnixNano(),
		op.Spec.VCPUs, op.Spec.MemoryMiB, b2i(op.UnknownOutcome), op.Spec.UUID, op.Spec.Fingerprint, op.Spec.ImageID,
		op.Spec.ImageSHA256, op.Spec.DiskGiB, op.Spec.SSHPublicKey, op.Spec.SSHFingerprint, op.Spec.Network, params)
	if err != nil {
		return Operation{}, false, internal(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Operation{}, false, internal(err)
	}
	if n == 0 { // replay: the existing operation, unchanged
		existing, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM operations WHERE project_id = ? AND idempotency_key = ?`,
			op.ProjectID, op.IdempotencyKey))
		if err != nil {
			return Operation{}, false, internal(err)
		}
		return existing, false, nil
	}
	if ev != nil {
		if err := insertAudit(ctx, tx, *ev); err != nil {
			return Operation{}, false, internal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, false, internal(err)
	}
	return op, true, nil
}

// Get implements Store.
func (s *SQLiteStore) Get(id string) (Operation, bool, error) {
	op, err := scan(s.db.QueryRowContext(context.Background(), `SELECT `+columns+` FROM operations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, false, nil
	}
	if err != nil {
		return Operation{}, false, internal(err)
	}
	return op, true, nil
}

// Update implements Store.
func (s *SQLiteStore) Update(op Operation) (Operation, error) { return s.update(op, nil) }

// UpdateAudited implements AuditedStore.
func (s *SQLiteStore) UpdateAudited(op Operation, ev AuditEvent) (Operation, error) {
	return s.update(op, &ev)
}

func (s *SQLiteStore) update(op Operation, ev *AuditEvent) (Operation, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, internal(err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE operations SET status = ?, attempts = ?, error_category = ?, updated_at = ?,
		unknown_outcome = ?, generation = generation + 1 WHERE id = ? AND generation = ?`,
		string(op.Status), op.Attempts, op.ErrorCategory, op.UpdatedAt.UnixNano(), b2i(op.UnknownOutcome), op.ID, op.Generation)
	if err != nil {
		if strings.Contains(err.Error(), "operation is terminal") || strings.Contains(err.Error(), "immutable") {
			return Operation{}, ErrStale
		}
		return Operation{}, internal(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Operation{}, internal(err)
	}
	if n == 0 {
		return Operation{}, ErrStale // unknown id or another writer got there first
	}
	if ev != nil {
		if err := insertAudit(ctx, tx, *ev); err != nil {
			return Operation{}, internal(err)
		}
	}
	saved, err := scan(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM operations WHERE id = ?`, op.ID))
	if err != nil {
		return Operation{}, internal(err)
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, internal(err)
	}
	return saved, nil
}

// NonTerminal implements Store.
func (s *SQLiteStore) NonTerminal() ([]Operation, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT `+columns+` FROM operations
		WHERE status IN ('pending','running','retryable_failure') ORDER BY seq`)
	if err != nil {
		return nil, internal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []Operation
	for rows.Next() {
		op, err := scan(rows)
		if err != nil {
			return nil, internal(err)
		}
		out = append(out, op)
	}
	if err := rows.Err(); err != nil {
		return nil, internal(err)
	}
	return out, nil
}

// Audit returns the stored audit events of an operation, oldest first (tests and the future history view).
func (s *SQLiteStore) Audit(operationID string) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT at, operation_id, project_id, actor, event, outcome, error_category
		FROM operation_audit WHERE operation_id = ? ORDER BY seq`, operationID)
	if err != nil {
		return nil, internal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		var (
			ev AuditEvent
			at int64
		)
		if err := rows.Scan(&at, &ev.OperationID, &ev.ProjectID, &ev.Actor, &ev.Event, &ev.Outcome, &ev.ErrorCategory); err != nil {
			return nil, internal(err)
		}
		ev.At = time.Unix(0, at).UTC()
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, internal(err)
	}
	return out, nil
}

var (
	_ AuditedStore = (*SQLiteStore)(nil)
	_ Store        = (*MemStore)(nil)
)

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Recent implements Lister: newest first by insertion sequence. It reads limit+1 rows to learn whether older operations remain.
func (s *SQLiteStore) Recent(limit int, after string) ([]Operation, bool, error) {
	q := `SELECT ` + columns + ` FROM operations`
	args := []any{}
	if after != "" {
		var seq int64
		if err := s.db.QueryRowContext(context.Background(), `SELECT seq FROM operations WHERE id = ?`, after).Scan(&seq); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, false, nil
			}
			return nil, false, internal(err)
		}
		q += ` WHERE seq < ?`
		args = append(args, seq)
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(context.Background(), q, args...)
	if err != nil {
		return nil, false, internal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []Operation
	for rows.Next() {
		op, err := scan(rows)
		if err != nil {
			return nil, false, internal(err)
		}
		out = append(out, op)
	}
	if err := rows.Err(); err != nil {
		return nil, false, internal(err)
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

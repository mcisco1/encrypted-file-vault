from __future__ import annotations

import uuid
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db: SQLAlchemy = SQLAlchemy()


def _uid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(db.Model):  # type: ignore[name-defined]
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=_uid)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    auth_verifier = db.Column(db.LargeBinary, nullable=False)
    kdf_salt = db.Column(db.LargeBinary, nullable=False)
    kdf_time_cost = db.Column(db.Integer, nullable=False, default=3)
    kdf_memory_cost = db.Column(db.Integer, nullable=False, default=65536)
    kdf_parallelism = db.Column(db.Integer, nullable=False, default=4)
    x25519_public_key = db.Column(db.LargeBinary, nullable=False)
    x25519_private_key_enc = db.Column(db.LargeBinary, nullable=False)
    x25519_private_key_nonce = db.Column(db.LargeBinary, nullable=False)
    totp_secret_enc = db.Column(db.LargeBinary, nullable=True)
    totp_nonce = db.Column(db.LargeBinary, nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
    files = db.relationship('VaultFile', backref='owner', lazy=True)


class VaultFile(db.Model):  # type: ignore[name-defined]
    __tablename__ = 'vault_files'
    id = db.Column(db.String(36), primary_key=True, default=_uid)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    filename_enc = db.Column(db.LargeBinary, nullable=False)
    filename_nonce = db.Column(db.LargeBinary, nullable=False)
    file_key_wrapped = db.Column(db.LargeBinary, nullable=False)
    file_key_nonce = db.Column(db.LargeBinary, nullable=False)
    current_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
    versions = db.relationship(
        'FileVersion', backref='vault_file', lazy=True,
        order_by='FileVersion.version_number.desc()',
    )


class FileVersion(db.Model):  # type: ignore[name-defined]
    __tablename__ = 'file_versions'
    id = db.Column(db.String(36), primary_key=True, default=_uid)
    file_id = db.Column(db.String(36), db.ForeignKey('vault_files.id'), nullable=False)
    version_number = db.Column(db.Integer, nullable=False)
    blob_path = db.Column(db.String(512), nullable=False)
    integrity_hash = db.Column(db.String(64), nullable=False)
    encrypted_size = db.Column(db.Integer, nullable=False)
    original_size = db.Column(db.Integer, nullable=False, default=0)
    nonce = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)


class SharedFile(db.Model):  # type: ignore[name-defined]
    __tablename__ = 'shared_files'
    id = db.Column(db.String(36), primary_key=True, default=_uid)
    file_id = db.Column(db.String(36), db.ForeignKey('vault_files.id'), nullable=False)
    sender_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    wrapped_key = db.Column(db.LargeBinary, nullable=False)
    key_nonce = db.Column(db.LargeBinary, nullable=False)
    sender_public_key = db.Column(db.LargeBinary, nullable=False)
    filename_enc = db.Column(db.LargeBinary, nullable=False)
    filename_nonce = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
    vault_file = db.relationship('VaultFile', backref='shares')
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])


class AuditLog(db.Model):  # type: ignore[name-defined]
    __tablename__ = 'audit_logs'
    id = db.Column(db.String(36), primary_key=True, default=_uid)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    target_file_id = db.Column(db.String(36), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=_utcnow)
    user = db.relationship('User', backref='audit_logs')

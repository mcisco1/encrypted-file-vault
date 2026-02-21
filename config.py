from __future__ import annotations

import os
import secrets

BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY: str = os.environ.get('VAULT_SECRET_KEY') or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI: str = 'sqlite:///' + os.path.join(BASE_DIR, 'vault.db')
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    STORAGE_PATH: str = os.path.join(BASE_DIR, 'storage')
    MAX_CONTENT_LENGTH: int = 100 * 1024 * 1024  # 100 MB
    MAX_VERSIONS: int = 5
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 4

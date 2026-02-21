from __future__ import annotations

import os
import sys
import tempfile
import base64
import hashlib

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure app BEFORE importing it
os.environ['FLASK_DEBUG'] = 'false'

from app import app, active_sessions, _login_attempts, _pending_2fa
from models import db

# Set test config once on the shared app instance
_storage_dir = tempfile.mkdtemp()
app.config.update({
    'TESTING': True,
    'ARGON2_TIME_COST': 1,
    'ARGON2_MEMORY_COST': 1024,
    'ARGON2_PARALLELISM': 1,
    'STORAGE_PATH': _storage_dir,
})


@pytest.fixture(autouse=True)
def reset_state():
    """Drop and recreate all tables + clear in-memory state for each test."""
    with app.app_context():
        db.drop_all()
        db.create_all()
    yield
    active_sessions.clear()
    _login_attempts.clear()
    _pending_2fa.clear()


@pytest.fixture()
def client():
    """Create a test client."""
    with app.test_client() as c:
        yield c


def make_pre_auth_key(password: str, username: str) -> str:
    """Replicate the client-side SHA-512(password + username) hashing."""
    data = (password + username.lower()).encode('utf-8')
    digest = hashlib.sha512(data).digest()
    return base64.b64encode(digest).decode('utf-8')


def register_user(client, username: str = 'testuser', password: str = 'SecureP@ss123') -> dict:
    """Register a user and return the response JSON."""
    pre_auth_key = make_pre_auth_key(password, username)
    resp = client.post('/api/auth/register', json={
        'username': username,
        'pre_auth_key': pre_auth_key,
    })
    return resp.get_json()


def login_user(client, username: str = 'testuser', password: str = 'SecureP@ss123') -> dict:
    """Login a user and return the response JSON."""
    pre_auth_key = make_pre_auth_key(password, username)
    resp = client.post('/api/auth/login', json={
        'username': username,
        'pre_auth_key': pre_auth_key,
    })
    return resp.get_json()

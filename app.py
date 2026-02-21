from __future__ import annotations

import os
import uuid
import base64
import secrets
import mimetypes
import time
import logging
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, TypedDict

from flask import (
    Flask, request, jsonify, g, Response,
    render_template, redirect, url_for, make_response,
)
from sqlalchemy import text
from config import Config
from models import db, User, VaultFile, FileVersion, SharedFile, AuditLog
from crypto_engine import CryptoEngine

# ── Logging ──

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger: logging.Logger = logging.getLogger('vault')

# ── App Setup ──

app: Flask = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

os.makedirs(app.config['STORAGE_PATH'], exist_ok=True)

with app.app_context():
    db.create_all()

logger.info('Vault application started')


# ── Session Types ──

class SessionData(TypedDict):
    user_id: str
    username: str
    master_key: bytes
    created_at: float
    last_active: float


# ── Session Management (with TTL and cleanup) ──

SESSION_TTL: int = 3600  # 1 hour

active_sessions: dict[str, SessionData] = {}


def create_session(user_id: str, username: str, master_key: bytes) -> str:
    token: str = secrets.token_hex(32)
    active_sessions[token] = {
        'user_id': user_id,
        'username': username,
        'master_key': master_key,
        'created_at': time.time(),
        'last_active': time.time(),
    }
    return token


def destroy_session(token: str) -> None:
    active_sessions.pop(token, None)


def get_session(token: str, extend: bool = True) -> SessionData | None:
    _cleanup_expired_sessions()
    sess: SessionData | None = active_sessions.get(token)
    if not sess:
        return None
    if time.time() - sess['last_active'] > SESSION_TTL:
        active_sessions.pop(token, None)
        return None
    if extend:
        sess['last_active'] = time.time()
    return sess


def _cleanup_expired_sessions() -> None:
    now: float = time.time()
    expired: list[str] = [t for t, s in active_sessions.items() if now - s['last_active'] > SESSION_TTL]
    for t in expired:
        active_sessions.pop(t, None)
    stale_ips: list[str] = [ip for ip, e in _login_attempts.items() if now - e['window_start'] > LOGIN_WINDOW]
    for ip in stale_ips:
        _login_attempts.pop(ip, None)
    # Clean expired 2FA temp tokens
    expired_2fa: list[str] = [t for t, d in _pending_2fa.items() if now - d['created_at'] > 300]
    for t in expired_2fa:
        _pending_2fa.pop(t, None)


# ── Rate Limiting ──

class RateLimitEntry(TypedDict):
    count: int
    window_start: float


_login_attempts: dict[str, RateLimitEntry] = {}
MAX_LOGIN_ATTEMPTS: int = 10
LOGIN_WINDOW: int = 300  # 5 minutes


def _check_rate_limit(ip: str) -> bool:
    now: float = time.time()
    entry: RateLimitEntry | None = _login_attempts.get(ip)
    if not entry or now - entry['window_start'] > LOGIN_WINDOW:
        _login_attempts[ip] = {'count': 1, 'window_start': now}
        return True
    if entry['count'] >= MAX_LOGIN_ATTEMPTS:
        logger.warning('Rate limit exceeded for IP %s', ip)
        return False
    entry['count'] += 1
    return True


def _reset_rate_limit(ip: str) -> None:
    _login_attempts.pop(ip, None)


# ── 2FA Pending Tokens ──

class Pending2FA(TypedDict):
    user_id: str
    username: str
    master_key: bytes
    created_at: float


_pending_2fa: dict[str, Pending2FA] = {}


# ── Middleware ──

@app.after_request
def set_security_headers(response: Response) -> Response:
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://unpkg.com; "
        "style-src 'self' https://fonts.googleapis.com https://unpkg.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


@app.errorhandler(413)
def request_entity_too_large(error: Exception) -> tuple[Response, int]:
    max_mb: int = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
    return jsonify({'success': False, 'error': f'File too large. Maximum size is {max_mb} MB'}), 413


@app.errorhandler(404)
def not_found(error: Exception) -> Response | tuple[Response, int]:
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Not found'}), 404
    return redirect(url_for('auth_page'))


@app.errorhandler(500)
def internal_error(error: Exception) -> Response | tuple[Response, int]:
    logger.error('Internal server error: %s', error)
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    return render_template('auth.html'), 500


# ── Auth Decorator ──

def require_auth(f: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        token: str | None = request.cookies.get('session_token')
        if not token:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            return redirect(url_for('auth_page'))
        sess: SessionData | None = get_session(token)
        if not sess:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Session expired'}), 401
            resp: Response = redirect(url_for('auth_page'))
            resp.delete_cookie('session_token')
            return resp
        g.user_id = sess['user_id']
        g.username = sess['username']
        g.master_key = sess['master_key']
        return f(*args, **kwargs)
    return wrapper


def _check_csrf() -> bool:
    if request.content_type and 'application/json' in request.content_type:
        return True
    if request.content_type and 'multipart/form-data' in request.content_type:
        origin: str = request.headers.get('Origin', '')
        referer: str = request.headers.get('Referer', '')
        host: str = request.host_url.rstrip('/')
        if origin and not origin.startswith(host):
            return False
        if referer and not referer.startswith(host):
            return False
    return True


# ── Helpers ──

def log_action(
    user_id: str,
    action: str,
    file_id: str | None = None,
    ip: str | None = None,
    details: str | None = None,
) -> None:
    entry: AuditLog = AuditLog(
        user_id=user_id,
        action=action,
        target_file_id=file_id,
        ip_address=ip,
        details=details,
    )
    db.session.add(entry)
    db.session.commit()


def find_file_by_name(user_id: str, master_key: bytes, filename: str) -> VaultFile | None:
    files: list[VaultFile] = VaultFile.query.filter_by(user_id=user_id).all()
    for f in files:
        try:
            name: str = CryptoEngine.decrypt(
                master_key, f.filename_enc, f.filename_nonce,
            ).decode('utf-8')
            if name == filename:
                return f
        except Exception:
            continue
    return None


def prune_versions(file_id: str, max_versions: int) -> None:
    versions: list[FileVersion] = (
        FileVersion.query
        .filter_by(file_id=file_id)
        .order_by(FileVersion.version_number.desc())
        .all()
    )
    if len(versions) > max_versions:
        for old in versions[max_versions:]:
            try:
                if os.path.exists(old.blob_path):
                    os.remove(old.blob_path)
            except OSError:
                pass
            db.session.delete(old)
        db.session.commit()


def serve_file(vault_file: VaultFile, version: FileVersion, file_key: bytes, filename: str) -> Response | tuple[Response, int]:
    if not os.path.exists(version.blob_path):
        return jsonify({'success': False, 'error': 'File blob missing from storage'}), 500

    with open(version.blob_path, 'rb') as fh:
        ciphertext: bytes = fh.read()

    if not CryptoEngine.verify_integrity(ciphertext, version.integrity_hash):
        return jsonify({'success': False, 'error': 'Integrity verification failed'}), 500

    aad: bytes = f"blob:{vault_file.id}:{version.version_number}".encode()
    try:
        plaintext: bytes = CryptoEngine.decrypt(file_key, ciphertext, version.nonce, aad)
    except Exception:
        return jsonify({'success': False, 'error': 'Decryption failed'}), 500

    mime: str = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    resp: Response = Response(plaintext, mimetype=mime)
    safe_name: str = filename.replace('"', '_').replace('\n', '_').replace('\r', '_')
    resp.headers['Content-Disposition'] = f'attachment; filename="{safe_name}"'
    resp.headers['Content-Length'] = str(len(plaintext))
    return resp


def _set_session_cookie(resp: Response, token: str) -> Response:
    is_secure: bool = not (app.debug or app.testing)
    resp.set_cookie(
        'session_token', token,
        httponly=True,
        samesite='Strict',
        secure=is_secure,
        max_age=SESSION_TTL,
    )
    return resp


# ── Health Endpoint ──

@app.route('/health', methods=['GET'])
def health_check() -> tuple[Response, int]:
    status: dict[str, Any] = {
        'status': 'healthy',
        'database': False,
        'storage': False,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
    try:
        db.session.execute(text('SELECT 1'))
        status['database'] = True
    except Exception as e:
        logger.error('Health check - database failure: %s', e)
        status['status'] = 'degraded'

    storage_path: str = app.config['STORAGE_PATH']
    if os.path.isdir(storage_path) and os.access(storage_path, os.W_OK):
        status['storage'] = True
    else:
        logger.error('Health check - storage directory not writable: %s', storage_path)
        status['status'] = 'degraded'

    code: int = 200 if status['status'] == 'healthy' else 503
    return jsonify(status), code


# ── Page Routes ──

@app.route('/')
def index() -> Response:
    token: str | None = request.cookies.get('session_token')
    if token and get_session(token):
        return redirect(url_for('vault_page'))
    return redirect(url_for('auth_page'))


@app.route('/auth')
def auth_page() -> str:
    return render_template('auth.html')


@app.route('/vault')
@require_auth
def vault_page() -> str:
    return render_template('dashboard.html', username=g.username)


@app.route('/vault/audit')
@require_auth
def audit_page() -> str:
    return render_template('audit.html', username=g.username)


@app.route('/docs')
def docs_page() -> str:
    return render_template('docs.html')


# ── Auth API ──

@app.route('/api/auth/register', methods=['POST'])
def register() -> tuple[Response, int] | Response:
    if not _check_csrf():
        return jsonify({'success': False, 'error': 'Invalid request origin'}), 403

    data: dict[str, Any] = request.get_json(silent=True) or {}
    username: str = data.get('username', '').strip().lower()
    pre_auth_key: str = data.get('pre_auth_key', '')

    if not username or not pre_auth_key:
        return jsonify({'success': False, 'error': 'Username and password are required'}), 400

    if len(username) < 3 or len(username) > 80:
        return jsonify({'success': False, 'error': 'Username must be 3-80 characters'}), 400

    if not username.isalnum() and not all(c.isalnum() or c in '-_.' for c in username):
        return jsonify({'success': False, 'error': 'Username can only contain letters, numbers, hyphens, underscores, and periods'}), 400

    try:
        pre_bytes: bytes = base64.b64decode(pre_auth_key, validate=True)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid authentication data'}), 400

    if len(pre_bytes) < 32:
        return jsonify({'success': False, 'error': 'Password does not meet minimum strength requirements'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'error': 'Username is already taken'}), 409

    master_key, auth_key, salt = CryptoEngine.derive_keys(
        pre_bytes,
        time_cost=app.config['ARGON2_TIME_COST'],
        memory_cost=app.config['ARGON2_MEMORY_COST'],
        parallelism=app.config['ARGON2_PARALLELISM'],
    )

    x25519_priv, x25519_pub = CryptoEngine.generate_x25519_keypair()
    priv_enc, priv_nonce = CryptoEngine.encrypt(master_key, x25519_priv)

    user: User = User(
        username=username,
        auth_verifier=CryptoEngine.auth_verifier(auth_key),
        kdf_salt=salt,
        kdf_time_cost=app.config['ARGON2_TIME_COST'],
        kdf_memory_cost=app.config['ARGON2_MEMORY_COST'],
        kdf_parallelism=app.config['ARGON2_PARALLELISM'],
        x25519_public_key=x25519_pub,
        x25519_private_key_enc=priv_enc,
        x25519_private_key_nonce=priv_nonce,
    )
    db.session.add(user)
    db.session.commit()

    token: str = create_session(user.id, username, master_key)
    log_action(user.id, 'register', ip=request.remote_addr)
    logger.info('User registered: %s', username)

    master_key_b64: str = base64.b64encode(master_key).decode()
    resp: Response = make_response(jsonify({'success': True, 'master_key': master_key_b64}))
    _set_session_cookie(resp, token)
    return resp


@app.route('/api/auth/login', methods=['POST'])
def login() -> tuple[Response, int] | Response:
    if not _check_csrf():
        return jsonify({'success': False, 'error': 'Invalid request origin'}), 403

    ip: str = request.remote_addr or '0.0.0.0'
    if not _check_rate_limit(ip):
        return jsonify({'success': False, 'error': 'Too many login attempts. Please try again later.'}), 429

    data: dict[str, Any] = request.get_json(silent=True) or {}
    username: str = data.get('username', '').strip().lower()
    pre_auth_key: str = data.get('pre_auth_key', '')

    if not username or not pre_auth_key:
        return jsonify({'success': False, 'error': 'Username and password are required'}), 400

    try:
        pre_bytes: bytes = base64.b64decode(pre_auth_key, validate=True)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    user: User | None = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    master_key, auth_key, _ = CryptoEngine.derive_keys(
        pre_bytes,
        salt=user.kdf_salt,
        time_cost=user.kdf_time_cost,
        memory_cost=user.kdf_memory_cost,
        parallelism=user.kdf_parallelism,
    )

    if not CryptoEngine.verify_auth(auth_key, user.auth_verifier):
        log_action(user.id, 'failed_login', ip=ip)
        logger.warning('Failed login for user: %s from IP: %s', username, ip)
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    # Check if 2FA is enabled
    if user.totp_enabled:
        temp_token: str = secrets.token_hex(32)
        _pending_2fa[temp_token] = {
            'user_id': user.id,
            'username': username,
            'master_key': master_key,
            'created_at': time.time(),
        }
        return jsonify({'success': True, 'requires_2fa': True, 'temp_token': temp_token})

    _reset_rate_limit(ip)
    token: str = create_session(user.id, username, master_key)
    log_action(user.id, 'login', ip=ip)
    logger.info('User logged in: %s', username)

    master_key_b64: str = base64.b64encode(master_key).decode()
    resp: Response = make_response(jsonify({'success': True, 'master_key': master_key_b64}))
    _set_session_cookie(resp, token)
    return resp


@app.route('/api/auth/logout', methods=['POST'])
def logout() -> Response:
    token: str | None = request.cookies.get('session_token')
    if token and token in active_sessions:
        uid: str = active_sessions[token]['user_id']
        log_action(uid, 'logout', ip=request.remote_addr)
        logger.info('User logged out: %s', active_sessions[token]['username'])
        destroy_session(token)
    resp: Response = make_response(jsonify({'success': True}))
    resp.delete_cookie('session_token')
    return resp


# ── 2FA API ──

@app.route('/api/auth/2fa/setup', methods=['POST'])
@require_auth
def setup_2fa() -> tuple[Response, int] | Response:
    try:
        import pyotp
    except ImportError:
        return jsonify({'success': False, 'error': '2FA not available'}), 501

    user: User | None = db.session.get(User, g.user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404

    if user.totp_enabled:
        return jsonify({'success': False, 'error': '2FA is already enabled'}), 400

    totp_secret: str = pyotp.random_base32()
    secret_bytes: bytes = totp_secret.encode('utf-8')
    enc_secret, nonce = CryptoEngine.encrypt(g.master_key, secret_bytes)

    user.totp_secret_enc = enc_secret
    user.totp_nonce = nonce
    db.session.commit()

    totp: pyotp.TOTP = pyotp.TOTP(totp_secret)
    provisioning_uri: str = totp.provisioning_uri(name=user.username, issuer_name='Vault')

    logger.info('2FA setup initiated for user: %s', g.username)
    return jsonify({
        'success': True,
        'secret': totp_secret,
        'provisioning_uri': provisioning_uri,
    })


@app.route('/api/auth/2fa/verify', methods=['POST'])
@require_auth
def verify_2fa() -> tuple[Response, int]:
    try:
        import pyotp
    except ImportError:
        return jsonify({'success': False, 'error': '2FA not available'}), 501

    data: dict[str, Any] = request.get_json(silent=True) or {}
    code: str = data.get('code', '').strip()

    if not code:
        return jsonify({'success': False, 'error': 'TOTP code is required'}), 400

    user: User | None = db.session.get(User, g.user_id)
    if not user or not user.totp_secret_enc:
        return jsonify({'success': False, 'error': '2FA not set up'}), 400

    totp_secret: str = CryptoEngine.decrypt(
        g.master_key, user.totp_secret_enc, user.totp_nonce,
    ).decode('utf-8')

    totp: pyotp.TOTP = pyotp.TOTP(totp_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'success': False, 'error': 'Invalid TOTP code'}), 401

    user.totp_enabled = True
    db.session.commit()

    log_action(g.user_id, '2fa_enabled', ip=request.remote_addr)
    logger.info('2FA enabled for user: %s', g.username)
    return jsonify({'success': True}), 200


@app.route('/api/auth/2fa/validate', methods=['POST'])
def validate_2fa() -> tuple[Response, int] | Response:
    try:
        import pyotp
    except ImportError:
        return jsonify({'success': False, 'error': '2FA not available'}), 501

    data: dict[str, Any] = request.get_json(silent=True) or {}
    temp_token: str = data.get('temp_token', '')
    code: str = data.get('code', '').strip()

    if not temp_token or not code:
        return jsonify({'success': False, 'error': 'Token and code are required'}), 400

    pending: Pending2FA | None = _pending_2fa.get(temp_token)
    if not pending:
        return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401

    if time.time() - pending['created_at'] > 300:
        _pending_2fa.pop(temp_token, None)
        return jsonify({'success': False, 'error': 'Token expired'}), 401

    user: User | None = db.session.get(User, pending['user_id'])
    if not user or not user.totp_secret_enc:
        _pending_2fa.pop(temp_token, None)
        return jsonify({'success': False, 'error': '2FA configuration error'}), 500

    totp_secret: str = CryptoEngine.decrypt(
        pending['master_key'], user.totp_secret_enc, user.totp_nonce,
    ).decode('utf-8')

    totp: pyotp.TOTP = pyotp.TOTP(totp_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'success': False, 'error': 'Invalid TOTP code'}), 401

    _pending_2fa.pop(temp_token, None)
    ip: str = request.remote_addr or '0.0.0.0'
    _reset_rate_limit(ip)
    token: str = create_session(user.id, pending['username'], pending['master_key'])
    log_action(user.id, 'login', ip=ip, details='with 2FA')
    logger.info('User logged in with 2FA: %s', pending['username'])

    master_key_b64: str = base64.b64encode(pending['master_key']).decode()
    resp: Response = make_response(jsonify({'success': True, 'master_key': master_key_b64}))
    _set_session_cookie(resp, token)
    return resp


@app.route('/api/auth/2fa/disable', methods=['POST'])
@require_auth
def disable_2fa() -> tuple[Response, int]:
    try:
        import pyotp
    except ImportError:
        return jsonify({'success': False, 'error': '2FA not available'}), 501

    data: dict[str, Any] = request.get_json(silent=True) or {}
    code: str = data.get('code', '').strip()

    if not code:
        return jsonify({'success': False, 'error': 'TOTP code is required'}), 400

    user: User | None = db.session.get(User, g.user_id)
    if not user or not user.totp_enabled or not user.totp_secret_enc:
        return jsonify({'success': False, 'error': '2FA is not enabled'}), 400

    totp_secret: str = CryptoEngine.decrypt(
        g.master_key, user.totp_secret_enc, user.totp_nonce,
    ).decode('utf-8')

    totp: pyotp.TOTP = pyotp.TOTP(totp_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'success': False, 'error': 'Invalid TOTP code'}), 401

    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_nonce = None
    db.session.commit()

    log_action(g.user_id, '2fa_disabled', ip=request.remote_addr)
    logger.info('2FA disabled for user: %s', g.username)
    return jsonify({'success': True}), 200


# ── Session Info API ──

@app.route('/api/auth/session', methods=['GET'])
def session_info() -> tuple[Response, int]:
    token: str | None = request.cookies.get('session_token')
    if not token:
        return jsonify({'success': False}), 401
    sess: SessionData | None = get_session(token, extend=False)
    if not sess:
        return jsonify({'success': False}), 401
    remaining: int = max(0, int(SESSION_TTL - (time.time() - sess['last_active'])))
    return jsonify({'success': True, 'remaining': remaining, 'ttl': SESSION_TTL}), 200


# ── File API ──

@app.route('/api/vault/files', methods=['GET'])
@require_auth
def list_files() -> Response:
    files: list[VaultFile] = (
        VaultFile.query
        .filter_by(user_id=g.user_id)
        .order_by(VaultFile.updated_at.desc())
        .all()
    )
    result: list[dict[str, Any]] = []
    for f in files:
        try:
            name: str = CryptoEngine.decrypt(
                g.master_key, f.filename_enc, f.filename_nonce,
            ).decode('utf-8')
        except Exception:
            name = '[decryption error]'

        versions: list[dict[str, Any]] = [
            {
                'version': v.version_number,
                'size': v.original_size,
                'created_at': v.created_at.isoformat(),
            }
            for v in f.versions
        ]

        latest: FileVersion | None = f.versions[0] if f.versions else None
        result.append({
            'id': f.id,
            'filename': name,
            'current_version': f.current_version,
            'size': latest.original_size if latest else 0,
            'versions': versions,
            'created_at': f.created_at.isoformat(),
            'updated_at': f.updated_at.isoformat(),
        })

    return jsonify({'success': True, 'files': result})


@app.route('/api/vault/upload', methods=['POST'])
@require_auth
def upload_file() -> tuple[Response, int] | Response:
    if not _check_csrf():
        return jsonify({'success': False, 'error': 'Invalid request origin'}), 403

    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    uploaded = request.files['file']
    if not uploaded.filename:
        return jsonify({'success': False, 'error': 'Empty filename'}), 400

    plaintext: bytes = uploaded.read()
    filename: str = uploaded.filename
    master_key: bytes = g.master_key

    existing: VaultFile | None = find_file_by_name(g.user_id, master_key, filename)

    if existing:
        vault_file: VaultFile = existing
        new_ver: int = vault_file.current_version + 1
        file_key: bytes = CryptoEngine.unwrap_key(
            master_key, vault_file.file_key_wrapped, vault_file.file_key_nonce,
        )
    else:
        file_id: str = str(uuid.uuid4())
        file_key = CryptoEngine.generate_file_key()
        wrapped, key_nonce = CryptoEngine.wrap_key(master_key, file_key)
        fname_enc, fname_nonce = CryptoEngine.encrypt(
            master_key, filename.encode('utf-8'),
        )
        vault_file = VaultFile(
            id=file_id,
            user_id=g.user_id,
            filename_enc=fname_enc,
            filename_nonce=fname_nonce,
            file_key_wrapped=wrapped,
            file_key_nonce=key_nonce,
            current_version=0,
        )
        db.session.add(vault_file)
        new_ver = 1

    aad: bytes = f"blob:{vault_file.id}:{new_ver}".encode()
    ciphertext, nonce = CryptoEngine.encrypt(file_key, plaintext, aad)

    blob_name: str = f"{vault_file.id}_v{new_ver}.enc"
    blob_path: str = os.path.join(app.config['STORAGE_PATH'], blob_name)
    with open(blob_path, 'wb') as fh:
        fh.write(ciphertext)

    integrity: str = CryptoEngine.integrity_hash(ciphertext)

    version: FileVersion = FileVersion(
        file_id=vault_file.id,
        version_number=new_ver,
        blob_path=blob_path,
        integrity_hash=integrity,
        encrypted_size=len(ciphertext),
        original_size=len(plaintext),
        nonce=nonce,
    )
    db.session.add(version)
    vault_file.current_version = new_ver
    vault_file.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    prune_versions(vault_file.id, app.config['MAX_VERSIONS'])
    log_action(g.user_id, 'file_upload', vault_file.id, request.remote_addr, f'v{new_ver}')
    logger.info('File uploaded by %s: %s v%d', g.username, filename, new_ver)

    return jsonify({'success': True, 'file_id': vault_file.id, 'version': new_ver})


@app.route('/api/vault/files/<file_id>/download', methods=['GET'])
@require_auth
def download_file(file_id: str) -> Response | tuple[Response, int]:
    vault_file: VaultFile | None = db.session.get(VaultFile, file_id)
    if not vault_file or vault_file.user_id != g.user_id:
        return jsonify({'success': False, 'error': 'File not found'}), 404

    version: FileVersion | None = FileVersion.query.filter_by(
        file_id=file_id, version_number=vault_file.current_version,
    ).first()
    if not version:
        return jsonify({'success': False, 'error': 'Version data missing'}), 500

    file_key: bytes = CryptoEngine.unwrap_key(
        g.master_key, vault_file.file_key_wrapped, vault_file.file_key_nonce,
    )
    filename: str = CryptoEngine.decrypt(
        g.master_key, vault_file.filename_enc, vault_file.filename_nonce,
    ).decode('utf-8')

    log_action(g.user_id, 'file_download', file_id, request.remote_addr, f'v{version.version_number}')
    return serve_file(vault_file, version, file_key, filename)


@app.route('/api/vault/files/<file_id>/download/<int:ver>', methods=['GET'])
@require_auth
def download_version(file_id: str, ver: int) -> Response | tuple[Response, int]:
    vault_file: VaultFile | None = db.session.get(VaultFile, file_id)
    if not vault_file or vault_file.user_id != g.user_id:
        return jsonify({'success': False, 'error': 'File not found'}), 404

    version: FileVersion | None = FileVersion.query.filter_by(
        file_id=file_id, version_number=ver,
    ).first()
    if not version:
        return jsonify({'success': False, 'error': 'Version not found'}), 404

    file_key: bytes = CryptoEngine.unwrap_key(
        g.master_key, vault_file.file_key_wrapped, vault_file.file_key_nonce,
    )
    filename: str = CryptoEngine.decrypt(
        g.master_key, vault_file.filename_enc, vault_file.filename_nonce,
    ).decode('utf-8')

    log_action(g.user_id, 'version_download', file_id, request.remote_addr, f'v{ver}')
    return serve_file(vault_file, version, file_key, filename)


@app.route('/api/vault/files/<file_id>', methods=['DELETE'])
@require_auth
def delete_file(file_id: str) -> tuple[Response, int]:
    vault_file: VaultFile | None = db.session.get(VaultFile, file_id)
    if not vault_file or vault_file.user_id != g.user_id:
        return jsonify({'success': False, 'error': 'File not found'}), 404

    for v in vault_file.versions:
        try:
            if os.path.exists(v.blob_path):
                os.remove(v.blob_path)
        except OSError:
            pass
        db.session.delete(v)

    SharedFile.query.filter_by(file_id=file_id).delete()
    db.session.delete(vault_file)
    db.session.commit()

    log_action(g.user_id, 'file_delete', file_id, request.remote_addr)
    logger.info('File deleted by %s: %s', g.username, file_id)
    return jsonify({'success': True}), 200


# ── Sharing API ──

@app.route('/api/vault/files/<file_id>/share', methods=['POST'])
@require_auth
def share_file(file_id: str) -> tuple[Response, int] | Response:
    if not _check_csrf():
        return jsonify({'success': False, 'error': 'Invalid request origin'}), 403

    data: dict[str, Any] = request.get_json(silent=True) or {}
    recipient_name: str = data.get('recipient', '').strip().lower()

    if not recipient_name:
        return jsonify({'success': False, 'error': 'Recipient username is required'}), 400

    vault_file: VaultFile | None = db.session.get(VaultFile, file_id)
    if not vault_file or vault_file.user_id != g.user_id:
        return jsonify({'success': False, 'error': 'File not found'}), 404

    recipient: User | None = User.query.filter_by(username=recipient_name).first()
    if not recipient:
        return jsonify({'success': False, 'error': 'Recipient not found'}), 404
    if recipient.id == g.user_id:
        return jsonify({'success': False, 'error': 'Cannot share with yourself'}), 400

    existing_share: SharedFile | None = SharedFile.query.filter_by(
        file_id=file_id, sender_id=g.user_id, recipient_id=recipient.id,
    ).first()
    if existing_share:
        return jsonify({'success': False, 'error': 'File is already shared with this user'}), 409

    sender: User | None = db.session.get(User, g.user_id)
    if not sender:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    sender_priv: bytes = CryptoEngine.decrypt(
        g.master_key, sender.x25519_private_key_enc, sender.x25519_private_key_nonce,
    )

    file_key: bytes = CryptoEngine.unwrap_key(
        g.master_key, vault_file.file_key_wrapped, vault_file.file_key_nonce,
    )

    wrapped, key_nonce = CryptoEngine.wrap_key_for_share(
        file_key, sender_priv, recipient.x25519_public_key,
    )

    original_name: bytes = CryptoEngine.decrypt(
        g.master_key, vault_file.filename_enc, vault_file.filename_nonce,
    )
    shared_secret: bytes = CryptoEngine.derive_shared_key(sender_priv, recipient.x25519_public_key)
    fname_enc, fname_nonce = CryptoEngine.encrypt(shared_secret, original_name)

    share: SharedFile = SharedFile(
        file_id=file_id,
        sender_id=g.user_id,
        recipient_id=recipient.id,
        wrapped_key=wrapped,
        key_nonce=key_nonce,
        sender_public_key=sender.x25519_public_key,
        filename_enc=fname_enc,
        filename_nonce=fname_nonce,
    )
    db.session.add(share)
    db.session.commit()

    log_action(g.user_id, 'file_share', file_id, request.remote_addr, f'to {recipient_name}')
    logger.info('File shared by %s to %s: %s', g.username, recipient_name, file_id)
    return jsonify({'success': True, 'share_id': share.id})


@app.route('/api/vault/shared', methods=['GET'])
@require_auth
def list_shared() -> Response:
    shares: list[SharedFile] = (
        SharedFile.query
        .filter_by(recipient_id=g.user_id)
        .order_by(SharedFile.created_at.desc())
        .all()
    )

    recipient: User | None = db.session.get(User, g.user_id)
    if not recipient:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    recip_priv: bytes = CryptoEngine.decrypt(
        g.master_key, recipient.x25519_private_key_enc, recipient.x25519_private_key_nonce,
    )

    result: list[dict[str, Any]] = []
    for s in shares:
        try:
            shared_secret: bytes = CryptoEngine.derive_shared_key(recip_priv, s.sender_public_key)
            name: str = CryptoEngine.decrypt(
                shared_secret, s.filename_enc, s.filename_nonce,
            ).decode('utf-8')
        except Exception:
            name = '[decryption error]'

        sender: User | None = db.session.get(User, s.sender_id)
        vault_file: VaultFile | None = db.session.get(VaultFile, s.file_id)
        latest: FileVersion | None = None
        if vault_file:
            latest = FileVersion.query.filter_by(
                file_id=vault_file.id, version_number=vault_file.current_version,
            ).first()

        result.append({
            'share_id': s.id,
            'file_id': s.file_id,
            'filename': name,
            'sender': sender.username if sender else 'unknown',
            'shared_at': s.created_at.isoformat(),
            'size': latest.original_size if latest else 0,
            'available': vault_file is not None,
        })

    return jsonify({'success': True, 'shared_files': result})


@app.route('/api/vault/shared/<share_id>/download', methods=['GET'])
@require_auth
def download_shared(share_id: str) -> Response | tuple[Response, int]:
    share: SharedFile | None = db.session.get(SharedFile, share_id)
    if not share or share.recipient_id != g.user_id:
        return jsonify({'success': False, 'error': 'Shared file not found'}), 404

    vault_file: VaultFile | None = db.session.get(VaultFile, share.file_id)
    if not vault_file:
        return jsonify({'success': False, 'error': 'Original file was deleted'}), 404

    recipient: User | None = db.session.get(User, g.user_id)
    if not recipient:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    recip_priv: bytes = CryptoEngine.decrypt(
        g.master_key, recipient.x25519_private_key_enc, recipient.x25519_private_key_nonce,
    )

    file_key: bytes = CryptoEngine.unwrap_shared_key(
        share.wrapped_key, share.key_nonce, recip_priv, share.sender_public_key,
    )

    shared_secret: bytes = CryptoEngine.derive_shared_key(recip_priv, share.sender_public_key)
    filename: str = CryptoEngine.decrypt(
        shared_secret, share.filename_enc, share.filename_nonce,
    ).decode('utf-8')

    version: FileVersion | None = FileVersion.query.filter_by(
        file_id=vault_file.id, version_number=vault_file.current_version,
    ).first()
    if not version:
        return jsonify({'success': False, 'error': 'Version data missing'}), 500

    log_action(g.user_id, 'shared_download', share.file_id, request.remote_addr, f'share {share_id}')
    return serve_file(vault_file, version, file_key, filename)


# ── Audit API ──

@app.route('/api/vault/audit', methods=['GET'])
@require_auth
def get_audit_log() -> Response:
    logs: list[AuditLog] = (
        AuditLog.query
        .filter_by(user_id=g.user_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(200)
        .all()
    )

    result: list[dict[str, Any]] = []
    for entry in logs:
        row: dict[str, Any] = {
            'id': entry.id,
            'action': entry.action,
            'ip_address': entry.ip_address or '',
            'timestamp': entry.timestamp.isoformat(),
            'details': entry.details or '',
            'filename': '',
        }
        if entry.target_file_id:
            vf: VaultFile | None = db.session.get(VaultFile, entry.target_file_id)
            if vf:
                try:
                    row['filename'] = CryptoEngine.decrypt(
                        g.master_key, vf.filename_enc, vf.filename_nonce,
                    ).decode('utf-8')
                except Exception:
                    row['filename'] = '[encrypted]'
            else:
                row['filename'] = '[deleted]'
        result.append(row)

    return jsonify({'success': True, 'logs': result})


if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', '').lower() == 'true', port=5000)

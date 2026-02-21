# Encrypted File Vault

A zero-knowledge encrypted file storage system built with Flask and modern cryptography. Files are encrypted client-side before upload — the server never sees plaintext content.

## Features

- **Zero-Knowledge Encryption** — AES-256-GCM client-side encryption via Web Crypto API
- **Argon2id Key Derivation** — Password → SHA-512 (client) → Argon2id KDF (server)
- **File Versioning** — Automatic version history with configurable retention
- **Secure File Sharing** — X25519 ECDH key exchange for sharing encrypted files between users
- **TOTP Two-Factor Authentication** — Optional 2FA with encrypted TOTP secrets
- **Audit Logging** — Complete access trail for all vault operations
- **Session Management** — Time-limited sessions with idle timeout
- **Rate Limiting** — Brute-force protection on authentication endpoints

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.12, Flask 3.0, SQLAlchemy |
| Crypto (server) | argon2-cffi, cryptography (X25519, HKDF, AES-256-GCM) |
| Crypto (client) | Web Crypto API (AES-GCM, SHA-512) |
| Database | SQLite |
| Auth | Argon2id + HKDF derived keys, TOTP 2FA |
| Deployment | Docker, Gunicorn |

## Cryptographic Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    KEY HIERARCHY                          │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Password (user)                                         │
│      │                                                   │
│      ▼                                                   │
│  SHA-512(password + username)  ← Client-side             │
│      │                                                   │
│      ▼                                                   │
│  pre_auth_key (base64)  ──────► Server                   │
│      │                                                   │
│      ▼                                                   │
│  Argon2id KDF (time=3, mem=64MB, par=4)                  │
│      │                                                   │
│      ├──► HKDF(info='vault-master-key-v1') → master_key  │
│      │        │                                          │
│      │        ├── Wrap/unwrap per-file keys               │
│      │        ├── Encrypt filenames                       │
│      │        └── Encrypt X25519 private key              │
│      │                                                   │
│      └──► HKDF(info='vault-auth-key-v1') → auth_key      │
│               │                                          │
│               └── SHA-256(auth_key) → auth_verifier       │
│                   (stored in DB for login verification)   │
│                                                          │
├──────────────────────────────────────────────────────────┤
│                   PER-FILE ENCRYPTION                     │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  file_key = random 256-bit key                           │
│      │                                                   │
│      ├── AES-256-GCM(file_key, plaintext, aad)           │
│      │   aad = "blob:{file_id}:{version}"                │
│      │                                                   │
│      └── Wrapped with master_key via AES-256-GCM         │
│                                                          │
├──────────────────────────────────────────────────────────┤
│                   FILE SHARING                            │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Sender X25519 private + Recipient X25519 public         │
│      │                                                   │
│      ▼                                                   │
│  ECDH → HKDF(info='vault-file-sharing-v1') → shared_key  │
│      │                                                   │
│      ├── Re-wrap file_key with shared_key                 │
│      └── Encrypt filename with shared_key                 │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Server compromise | Server never sees plaintext file content (zero-knowledge). Passwords never transmitted — only SHA-512 pre-hash sent. |
| Database theft | File keys wrapped with master_key. Auth uses Argon2id with 64MB memory cost. TOTP secrets encrypted. |
| Brute-force attacks | Rate limiting (10 attempts / 5 min), Argon2id slow hashing. |
| Session hijacking | HttpOnly + SameSite=Strict cookies, 1-hour TTL with idle timeout. |
| CSRF | Origin/Referer validation, JSON Content-Type enforcement. |
| XSS | CSP headers, input sanitization, no inline scripts. |
| MITM | Secure cookie flag in production, HSTS-ready. |

### Trust Boundaries

The server is **semi-trusted**: it performs key derivation and key wrapping for sharing, but never accesses plaintext file content. The master_key is returned to the client after authentication and used for client-side operations.

## Quick Start

### Local Development

```bash
# Clone and enter directory
cd encrypted-file-vault

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Visit `http://localhost:5000` to access the vault.

### Docker

```bash
# Build and run
docker compose up --build

# Or using Docker directly
docker build -t vault .
docker run -p 5000:5000 -v vault_data:/app/storage vault
```

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Health check (DB + storage) |
| `GET` | `/docs` | No | Swagger API documentation |
| `POST` | `/api/auth/register` | No | Create account |
| `POST` | `/api/auth/login` | No | Sign in |
| `POST` | `/api/auth/logout` | No | Sign out |
| `GET` | `/api/auth/session` | Yes | Session info (TTL remaining) |
| `POST` | `/api/auth/2fa/setup` | Yes | Generate TOTP secret |
| `POST` | `/api/auth/2fa/verify` | Yes | Enable 2FA |
| `POST` | `/api/auth/2fa/validate` | No | Validate TOTP during login |
| `POST` | `/api/auth/2fa/disable` | Yes | Disable 2FA |
| `GET` | `/api/vault/files` | Yes | List encrypted files |
| `POST` | `/api/vault/upload` | Yes | Upload and encrypt file |
| `GET` | `/api/vault/files/:id/download` | Yes | Download latest version |
| `GET` | `/api/vault/files/:id/download/:ver` | Yes | Download specific version |
| `DELETE` | `/api/vault/files/:id` | Yes | Delete file and all versions |
| `POST` | `/api/vault/files/:id/share` | Yes | Share file with another user |
| `GET` | `/api/vault/shared` | Yes | List files shared with me |
| `GET` | `/api/vault/shared/:id/download` | Yes | Download shared file |
| `GET` | `/api/vault/audit` | Yes | Access audit log |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_SECRET_KEY` | random | Flask secret key |
| `FLASK_DEBUG` | `false` | Enable debug mode |
| `ARGON2_TIME_COST` | `3` | Argon2id iterations |
| `ARGON2_MEMORY_COST` | `65536` | Argon2id memory (KB) |
| `ARGON2_PARALLELISM` | `4` | Argon2id threads |

## Testing

```bash
pip install pytest
pytest tests/ -v
```

## Project Structure

```
encrypted-file-vault/
├── app.py               # Flask application, routes, session management
├── crypto_engine.py     # Cryptographic operations (AES-GCM, X25519, Argon2id)
├── models.py            # SQLAlchemy models (User, VaultFile, SharedFile, AuditLog)
├── config.py            # Application configuration
├── requirements.txt     # Python dependencies
├── Dockerfile           # Container image definition
├── docker-compose.yml   # Container orchestration
├── static/
│   ├── css/vault.css    # Dark-themed UI styles
│   ├── js/vault.js      # Client-side encryption, auth, vault UI
│   └── openapi.yaml     # OpenAPI 3.0 specification
├── templates/
│   ├── base.html        # Base template
│   ├── auth.html        # Login / registration page
│   ├── dashboard.html   # Vault dashboard
│   ├── audit.html       # Audit log viewer
│   └── docs.html        # Swagger UI documentation
└── tests/
    ├── conftest.py      # Test fixtures
    ├── test_crypto_engine.py  # Crypto unit tests
    └── test_api.py      # API integration tests
```

## Security Considerations

- **Never reuse passwords** — the master key is derived from your password. A compromised password means compromised vault.
- **TOTP 2FA** — strongly recommended for production use. TOTP secrets are encrypted with your master key.
- **Session timeout** — sessions expire after 1 hour of inactivity. The client displays a countdown timer.
- **Backup your data** — the `storage/` directory and `vault.db` contain all encrypted files and metadata.

from __future__ import annotations

import os
import hashlib
import hmac

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

SALT_LENGTH: int = 32
NONCE_LENGTH: int = 12
KEY_LENGTH: int = 32


class CryptoEngine:

    @staticmethod
    def derive_keys(
        pre_auth_key: bytes,
        salt: bytes | None = None,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
    ) -> tuple[bytes, bytes, bytes]:
        if salt is None:
            salt = os.urandom(SALT_LENGTH)

        root_key: bytes = hash_secret_raw(
            secret=pre_auth_key,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=KEY_LENGTH,
            type=Type.ID,
        )

        master_key: bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=None,
            info=b'vault-master-key-v1',
        ).derive(root_key)

        auth_key: bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=None,
            info=b'vault-auth-key-v1',
        ).derive(root_key)

        return master_key, auth_key, salt

    @staticmethod
    def generate_file_key() -> bytes:
        return os.urandom(KEY_LENGTH)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
        nonce: bytes = os.urandom(NONCE_LENGTH)
        ciphertext: bytes = AESGCM(key).encrypt(nonce, plaintext, aad)
        return ciphertext, nonce

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes | None = None) -> bytes:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    @staticmethod
    def wrap_key(master_key: bytes, file_key: bytes) -> tuple[bytes, bytes]:
        return CryptoEngine.encrypt(master_key, file_key)

    @staticmethod
    def unwrap_key(master_key: bytes, wrapped: bytes, nonce: bytes) -> bytes:
        return CryptoEngine.decrypt(master_key, wrapped, nonce)

    @staticmethod
    def generate_x25519_keypair() -> tuple[bytes, bytes]:
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        priv_bytes: bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes: bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv_bytes, pub_bytes

    @staticmethod
    def derive_shared_key(private_bytes: bytes, public_bytes: bytes) -> bytes:
        private_key = X25519PrivateKey.from_private_bytes(private_bytes)
        public_key = X25519PublicKey.from_public_bytes(public_bytes)
        shared: bytes = private_key.exchange(public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=None,
            info=b'vault-file-sharing-v1',
        ).derive(shared)

    @staticmethod
    def wrap_key_for_share(file_key: bytes, sender_priv: bytes, recipient_pub: bytes) -> tuple[bytes, bytes]:
        shared: bytes = CryptoEngine.derive_shared_key(sender_priv, recipient_pub)
        return CryptoEngine.encrypt(shared, file_key)

    @staticmethod
    def unwrap_shared_key(wrapped: bytes, nonce: bytes, recipient_priv: bytes, sender_pub: bytes) -> bytes:
        shared: bytes = CryptoEngine.derive_shared_key(recipient_priv, sender_pub)
        return CryptoEngine.decrypt(shared, wrapped, nonce)

    @staticmethod
    def integrity_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def verify_integrity(data: bytes, expected: str) -> bool:
        return hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected)

    @staticmethod
    def auth_verifier(auth_key: bytes) -> bytes:
        return hashlib.sha256(auth_key).digest()

    @staticmethod
    def verify_auth(auth_key: bytes, stored: bytes) -> bool:
        return hmac.compare_digest(hashlib.sha256(auth_key).digest(), stored)

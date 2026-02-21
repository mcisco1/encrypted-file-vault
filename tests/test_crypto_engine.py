from __future__ import annotations

import os
import pytest
from crypto_engine import CryptoEngine


class TestDeriveKeys:
    def test_deterministic_with_same_salt(self):
        pre_key = os.urandom(64)
        salt = os.urandom(32)
        mk1, ak1, s1 = CryptoEngine.derive_keys(pre_key, salt=salt, time_cost=1, memory_cost=1024, parallelism=1)
        mk2, ak2, s2 = CryptoEngine.derive_keys(pre_key, salt=salt, time_cost=1, memory_cost=1024, parallelism=1)
        assert mk1 == mk2
        assert ak1 == ak2
        assert s1 == s2

    def test_different_salt_different_keys(self):
        pre_key = os.urandom(64)
        mk1, ak1, s1 = CryptoEngine.derive_keys(pre_key, time_cost=1, memory_cost=1024, parallelism=1)
        mk2, ak2, s2 = CryptoEngine.derive_keys(pre_key, time_cost=1, memory_cost=1024, parallelism=1)
        assert s1 != s2
        assert mk1 != mk2

    def test_master_key_and_auth_key_differ(self):
        pre_key = os.urandom(64)
        mk, ak, _ = CryptoEngine.derive_keys(pre_key, time_cost=1, memory_cost=1024, parallelism=1)
        assert mk != ak

    def test_key_lengths(self):
        pre_key = os.urandom(64)
        mk, ak, salt = CryptoEngine.derive_keys(pre_key, time_cost=1, memory_cost=1024, parallelism=1)
        assert len(mk) == 32
        assert len(ak) == 32
        assert len(salt) == 32


class TestEncryptDecrypt:
    def test_roundtrip(self):
        key = CryptoEngine.generate_file_key()
        plaintext = b'Hello, encrypted world!'
        ciphertext, nonce = CryptoEngine.encrypt(key, plaintext)
        result = CryptoEngine.decrypt(key, ciphertext, nonce)
        assert result == plaintext

    def test_roundtrip_with_aad(self):
        key = CryptoEngine.generate_file_key()
        plaintext = b'secret data'
        aad = b'blob:file123:1'
        ciphertext, nonce = CryptoEngine.encrypt(key, plaintext, aad)
        result = CryptoEngine.decrypt(key, ciphertext, nonce, aad)
        assert result == plaintext

    def test_wrong_key_fails(self):
        key1 = CryptoEngine.generate_file_key()
        key2 = CryptoEngine.generate_file_key()
        ciphertext, nonce = CryptoEngine.encrypt(key1, b'secret')
        with pytest.raises(Exception):
            CryptoEngine.decrypt(key2, ciphertext, nonce)

    def test_tampered_ciphertext_fails(self):
        key = CryptoEngine.generate_file_key()
        ciphertext, nonce = CryptoEngine.encrypt(key, b'secret data')
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            CryptoEngine.decrypt(key, bytes(tampered), nonce)

    def test_wrong_aad_fails(self):
        key = CryptoEngine.generate_file_key()
        ciphertext, nonce = CryptoEngine.encrypt(key, b'data', b'correct_aad')
        with pytest.raises(Exception):
            CryptoEngine.decrypt(key, ciphertext, nonce, b'wrong_aad')


class TestKeyWrapping:
    def test_wrap_unwrap_roundtrip(self):
        master_key = CryptoEngine.generate_file_key()
        file_key = CryptoEngine.generate_file_key()
        wrapped, nonce = CryptoEngine.wrap_key(master_key, file_key)
        unwrapped = CryptoEngine.unwrap_key(master_key, wrapped, nonce)
        assert unwrapped == file_key


class TestX25519Sharing:
    def test_shared_key_agreement(self):
        priv_a, pub_a = CryptoEngine.generate_x25519_keypair()
        priv_b, pub_b = CryptoEngine.generate_x25519_keypair()
        shared_ab = CryptoEngine.derive_shared_key(priv_a, pub_b)
        shared_ba = CryptoEngine.derive_shared_key(priv_b, pub_a)
        assert shared_ab == shared_ba
        assert len(shared_ab) == 32

    def test_wrap_key_for_share_roundtrip(self):
        priv_sender, pub_sender = CryptoEngine.generate_x25519_keypair()
        priv_recip, pub_recip = CryptoEngine.generate_x25519_keypair()
        file_key = CryptoEngine.generate_file_key()

        wrapped, nonce = CryptoEngine.wrap_key_for_share(file_key, priv_sender, pub_recip)
        unwrapped = CryptoEngine.unwrap_shared_key(wrapped, nonce, priv_recip, pub_sender)
        assert unwrapped == file_key


class TestIntegrity:
    def test_integrity_hash_verify(self):
        data = b'important encrypted data'
        h = CryptoEngine.integrity_hash(data)
        assert CryptoEngine.verify_integrity(data, h) is True

    def test_integrity_hash_tampered(self):
        data = b'important encrypted data'
        h = CryptoEngine.integrity_hash(data)
        tampered = bytearray(data)
        tampered[0] ^= 0xFF
        assert CryptoEngine.verify_integrity(bytes(tampered), h) is False


class TestAuth:
    def test_auth_verifier_roundtrip(self):
        auth_key = os.urandom(32)
        verifier = CryptoEngine.auth_verifier(auth_key)
        assert CryptoEngine.verify_auth(auth_key, verifier) is True

    def test_auth_verifier_wrong_key(self):
        auth_key = os.urandom(32)
        verifier = CryptoEngine.auth_verifier(auth_key)
        wrong_key = os.urandom(32)
        assert CryptoEngine.verify_auth(wrong_key, verifier) is False


class TestFileKeyRandomness:
    def test_file_keys_are_unique(self):
        keys = [CryptoEngine.generate_file_key() for _ in range(100)]
        assert len(set(keys)) == 100

    def test_file_key_length(self):
        key = CryptoEngine.generate_file_key()
        assert len(key) == 32

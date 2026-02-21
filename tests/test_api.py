from __future__ import annotations

import io
import time
import pytest

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.conftest import register_user, login_user, make_pre_auth_key
from app import active_sessions, _login_attempts, MAX_LOGIN_ATTEMPTS


class TestAuth:
    def test_register(self, client):
        result = register_user(client)
        assert result['success'] is True
        assert 'master_key' in result

    def test_register_duplicate(self, client):
        register_user(client)
        result = register_user(client)
        assert result['success'] is False
        assert 'already taken' in result['error']

    def test_register_short_username(self, client):
        pre = make_pre_auth_key('SecureP@ss123', 'ab')
        resp = client.post('/api/auth/register', json={
            'username': 'ab',
            'pre_auth_key': pre,
        })
        result = resp.get_json()
        assert result['success'] is False
        assert '3-80' in result['error']

    def test_login(self, client):
        register_user(client)
        # Logout first
        client.post('/api/auth/logout')
        result = login_user(client)
        assert result['success'] is True
        assert 'master_key' in result

    def test_login_bad_password(self, client):
        register_user(client)
        client.post('/api/auth/logout')
        pre = make_pre_auth_key('WrongPassword1!', 'testuser')
        resp = client.post('/api/auth/login', json={
            'username': 'testuser',
            'pre_auth_key': pre,
        })
        result = resp.get_json()
        assert result['success'] is False
        assert 'Invalid credentials' in result['error']

    def test_login_nonexistent_user(self, client):
        pre = make_pre_auth_key('SecureP@ss123', 'nouser')
        resp = client.post('/api/auth/login', json={
            'username': 'nouser',
            'pre_auth_key': pre,
        })
        assert resp.get_json()['success'] is False

    def test_logout(self, client):
        register_user(client)
        resp = client.post('/api/auth/logout')
        result = resp.get_json()
        assert result['success'] is True

    def test_username_validation(self, client):
        pre = make_pre_auth_key('SecureP@ss123', 'bad user!')
        resp = client.post('/api/auth/register', json={
            'username': 'bad user!',
            'pre_auth_key': pre,
        })
        result = resp.get_json()
        assert result['success'] is False
        assert 'letters' in result['error']


class TestSession:
    def test_session_info(self, client):
        register_user(client)
        resp = client.get('/api/auth/session')
        result = resp.get_json()
        assert result['success'] is True
        assert 'remaining' in result
        assert result['remaining'] > 0
        assert result['ttl'] == 3600

    def test_unauthenticated_session(self, client):
        resp = client.get('/api/auth/session')
        assert resp.status_code == 401


class TestFiles:
    def test_upload(self, client):
        register_user(client)
        data = {'file': (io.BytesIO(b'hello world'), 'test.txt')}
        resp = client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
        result = resp.get_json()
        assert result['success'] is True
        assert 'file_id' in result
        assert result['version'] == 1

    def test_list_files(self, client):
        register_user(client)
        data = {'file': (io.BytesIO(b'content'), 'doc.txt')}
        client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
        resp = client.get('/api/vault/files')
        result = resp.get_json()
        assert result['success'] is True
        assert len(result['files']) == 1
        assert result['files'][0]['filename'] == 'doc.txt'

    def test_download(self, client):
        register_user(client)
        content = b'my secret document content'
        data = {'file': (io.BytesIO(content), 'secret.txt')}
        upload = client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
        file_id = upload.get_json()['file_id']

        resp = client.get(f'/api/vault/files/{file_id}/download')
        assert resp.status_code == 200
        assert resp.data == content

    def test_upload_new_version(self, client):
        register_user(client)
        data1 = {'file': (io.BytesIO(b'version 1'), 'versioned.txt')}
        client.post('/api/vault/upload', data=data1, content_type='multipart/form-data')
        data2 = {'file': (io.BytesIO(b'version 2'), 'versioned.txt')}
        upload2 = client.post('/api/vault/upload', data=data2, content_type='multipart/form-data')
        result = upload2.get_json()
        assert result['success'] is True
        assert result['version'] == 2

    def test_download_specific_version(self, client):
        register_user(client)
        data1 = {'file': (io.BytesIO(b'v1 content'), 'multi.txt')}
        upload1 = client.post('/api/vault/upload', data=data1, content_type='multipart/form-data')
        file_id = upload1.get_json()['file_id']
        data2 = {'file': (io.BytesIO(b'v2 content'), 'multi.txt')}
        client.post('/api/vault/upload', data=data2, content_type='multipart/form-data')

        resp_v1 = client.get(f'/api/vault/files/{file_id}/download/1')
        assert resp_v1.data == b'v1 content'

        resp_v2 = client.get(f'/api/vault/files/{file_id}/download/2')
        assert resp_v2.data == b'v2 content'

    def test_delete_file(self, client):
        register_user(client)
        data = {'file': (io.BytesIO(b'delete me'), 'delete.txt')}
        upload = client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
        file_id = upload.get_json()['file_id']

        resp = client.delete(f'/api/vault/files/{file_id}')
        assert resp.get_json()['success'] is True

        # Verify it's gone
        resp = client.get('/api/vault/files')
        assert len(resp.get_json()['files']) == 0

    def test_download_nonexistent(self, client):
        register_user(client)
        resp = client.get('/api/vault/files/nonexistent-id/download')
        assert resp.status_code == 404

    def test_upload_no_file(self, client):
        register_user(client)
        resp = client.post('/api/vault/upload', data={}, content_type='multipart/form-data')
        assert resp.get_json()['success'] is False


class TestSharing:
    def test_share_file(self, client):
        register_user(client, 'alice', 'SecureP@ss123')
        data = {'file': (io.BytesIO(b'shared content'), 'shared.txt')}
        upload = client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
        file_id = upload.get_json()['file_id']
        client.post('/api/auth/logout')

        register_user(client, 'bob', 'SecureP@ss456')
        client.post('/api/auth/logout')

        login_user(client, 'alice', 'SecureP@ss123')
        resp = client.post(f'/api/vault/files/{file_id}/share', json={'recipient': 'bob'})
        result = resp.get_json()
        assert result['success'] is True
        assert 'share_id' in result

    def test_duplicate_share_blocked(self, client):
        register_user(client, 'alice', 'SecureP@ss123')
        data = {'file': (io.BytesIO(b'data'), 'file.txt')}
        upload = client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
        file_id = upload.get_json()['file_id']
        client.post('/api/auth/logout')

        register_user(client, 'bob', 'SecureP@ss456')
        client.post('/api/auth/logout')

        login_user(client, 'alice', 'SecureP@ss123')
        client.post(f'/api/vault/files/{file_id}/share', json={'recipient': 'bob'})
        resp = client.post(f'/api/vault/files/{file_id}/share', json={'recipient': 'bob'})
        assert resp.get_json()['success'] is False
        assert 'already shared' in resp.get_json()['error']

    def test_share_with_self_blocked(self, client):
        register_user(client, 'alice', 'SecureP@ss123')
        data = {'file': (io.BytesIO(b'data'), 'file.txt')}
        upload = client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
        file_id = upload.get_json()['file_id']

        resp = client.post(f'/api/vault/files/{file_id}/share', json={'recipient': 'alice'})
        assert resp.get_json()['success'] is False

    def test_download_shared(self, client):
        register_user(client, 'alice', 'SecureP@ss123')
        content = b'shared secret data'
        data = {'file': (io.BytesIO(content), 'secret.txt')}
        upload = client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
        file_id = upload.get_json()['file_id']
        client.post('/api/auth/logout')

        register_user(client, 'bob', 'SecureP@ss456')
        client.post('/api/auth/logout')

        login_user(client, 'alice', 'SecureP@ss123')
        share_resp = client.post(f'/api/vault/files/{file_id}/share', json={'recipient': 'bob'})
        share_id = share_resp.get_json()['share_id']
        client.post('/api/auth/logout')

        login_user(client, 'bob', 'SecureP@ss456')
        resp = client.get(f'/api/vault/shared/{share_id}/download')
        assert resp.status_code == 200
        assert resp.data == content

    def test_list_shared(self, client):
        register_user(client, 'alice', 'SecureP@ss123')
        data = {'file': (io.BytesIO(b'data'), 'file.txt')}
        upload = client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
        file_id = upload.get_json()['file_id']
        client.post('/api/auth/logout')

        register_user(client, 'bob', 'SecureP@ss456')
        client.post('/api/auth/logout')

        login_user(client, 'alice', 'SecureP@ss123')
        client.post(f'/api/vault/files/{file_id}/share', json={'recipient': 'bob'})
        client.post('/api/auth/logout')

        login_user(client, 'bob', 'SecureP@ss456')
        resp = client.get('/api/vault/shared')
        result = resp.get_json()
        assert result['success'] is True
        assert len(result['shared_files']) == 1
        assert result['shared_files'][0]['filename'] == 'file.txt'


class TestAudit:
    def test_audit_log(self, client):
        register_user(client)
        resp = client.get('/api/vault/audit')
        result = resp.get_json()
        assert result['success'] is True
        assert len(result['logs']) > 0
        actions = [l['action'] for l in result['logs']]
        assert 'register' in actions


class TestSecurity:
    def test_rate_limiting(self, client):
        register_user(client)
        client.post('/api/auth/logout')

        bad_pre = make_pre_auth_key('wrong', 'testuser')
        for i in range(MAX_LOGIN_ATTEMPTS):
            client.post('/api/auth/login', json={
                'username': 'testuser',
                'pre_auth_key': bad_pre,
            })

        resp = client.post('/api/auth/login', json={
            'username': 'testuser',
            'pre_auth_key': bad_pre,
        })
        assert resp.status_code == 429

    def test_auth_required(self, client):
        resp = client.get('/api/vault/files')
        assert resp.status_code == 401

    def test_security_headers(self, client):
        resp = client.get('/health')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
        assert resp.headers.get('X-Frame-Options') == 'DENY'
        assert 'Content-Security-Policy' in resp.headers

    def test_invalid_session_token(self, client):
        client.set_cookie('session_token', 'invalid-token-value', domain='localhost')
        resp = client.get('/api/vault/files')
        assert resp.status_code == 401


class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get('/health')
        result = resp.get_json()
        assert result['status'] == 'healthy'
        assert result['database'] is True
        assert result['storage'] is True
        assert 'timestamp' in result

    def test_health_no_auth_required(self, client):
        resp = client.get('/health')
        assert resp.status_code == 200


class TestPageRoutes:
    def test_root_redirects_to_auth(self, client):
        resp = client.get('/')
        assert resp.status_code == 302

    def test_vault_requires_auth(self, client):
        resp = client.get('/vault')
        assert resp.status_code == 302

    def test_docs_page(self, client):
        resp = client.get('/docs')
        assert resp.status_code == 200
        assert b'swagger' in resp.data.lower()

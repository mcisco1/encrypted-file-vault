(function () {
    'use strict';

    function $(sel, root) { return (root || document).querySelector(sel); }
    function $$(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

    async function hashPassword(password, username) {
        var encoder = new TextEncoder();
        var data = encoder.encode(password + username.toLowerCase());
        var buf = await crypto.subtle.digest('SHA-512', data);
        var bytes = new Uint8Array(buf);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }

    async function api(url, opts) {
        opts = opts || {};
        try {
            var res = await fetch(url, opts);
            if (res.status === 401 && !url.includes('/api/auth/')) {
                window.location.href = '/auth';
                return null;
            }
            if (res.status === 413) {
                return { success: false, error: 'File too large. Maximum size is 100 MB.' };
            }
            if (res.status === 429) {
                return { success: false, error: 'Too many attempts. Please wait a few minutes.' };
            }
            var ct = res.headers.get('content-type') || '';
            if (ct.includes('application/json')) return res.json();
            return res;
        } catch (err) {
            return { success: false, error: 'Network error — check your connection' };
        }
    }

    function toast(msg, type) {
        type = type || 'info';
        var container = $('#toast-container');
        if (!container) return;
        var el = document.createElement('div');
        el.className = 'toast ' + type;
        el.textContent = msg;
        container.appendChild(el);
        setTimeout(function () {
            el.classList.add('fade-out');
            setTimeout(function () { el.remove(); }, 200);
        }, 3500);
    }

    function formatSize(bytes) {
        if (bytes <= 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        if (i >= units.length) i = units.length - 1;
        return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
    }

    function formatDate(iso) {
        var d = new Date(iso);
        var now = new Date();
        var diff = now - d;
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
        if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    }

    function fileTypeInfo(filename) {
        var ext = (filename.split('.').pop() || '').toLowerCase();
        var map = {
            pdf: ['PDF', 'pdf'], doc: ['DOC', 'doc'], docx: ['DOC', 'doc'], txt: ['TXT', 'doc'],
            xls: ['XLS', 'doc'], xlsx: ['XLS', 'doc'], csv: ['CSV', 'doc'], ppt: ['PPT', 'doc'],
            png: ['PNG', 'img'], jpg: ['JPG', 'img'], jpeg: ['JPG', 'img'], gif: ['GIF', 'img'],
            svg: ['SVG', 'img'], webp: ['WEB', 'img'], bmp: ['BMP', 'img'],
            zip: ['ZIP', 'zip'], rar: ['RAR', 'zip'], '7z': ['7Z', 'zip'], tar: ['TAR', 'zip'], gz: ['GZ', 'zip'],
            js: ['JS', 'code'], py: ['PY', 'code'], html: ['HTM', 'code'], css: ['CSS', 'code'],
            json: ['JSN', 'code'], xml: ['XML', 'code'], java: ['JAV', 'code'], cpp: ['C++', 'code'],
            rs: ['RS', 'code'], go: ['GO', 'code'], ts: ['TS', 'code'], rb: ['RB', 'code'],
            mp3: ['MP3', 'media'], mp4: ['MP4', 'media'], mov: ['MOV', 'media'],
            wav: ['WAV', 'media'], avi: ['AVI', 'media'], mkv: ['MKV', 'media'],
        };
        var info = map[ext];
        return info ? { label: info[0], cls: info[1] } : { label: ext ? ext.substring(0, 3).toUpperCase() : 'FIL', cls: 'default' };
    }


    // ── Client-Side Crypto Module ──

    var CryptoModule = {
        masterKey: null,

        setMasterKey: async function (b64) {
            var raw = Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); });
            this.masterKey = await crypto.subtle.importKey(
                'raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
            );
        },

        hasMasterKey: function () {
            return this.masterKey !== null;
        },

        generateFileKey: async function () {
            return crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
            );
        },

        encrypt: async function (fileKey, plaintext) {
            var iv = crypto.getRandomValues(new Uint8Array(12));
            var ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv }, fileKey, plaintext
            );
            return { ciphertext: new Uint8Array(ciphertext), iv: iv };
        },

        decrypt: async function (fileKey, ciphertext, iv) {
            var plaintext = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv }, fileKey, ciphertext
            );
            return new Uint8Array(plaintext);
        },

        wrapFileKey: async function (fileKey) {
            var iv = crypto.getRandomValues(new Uint8Array(12));
            var wrapped = await crypto.subtle.wrapKey(
                'raw', fileKey, this.masterKey, { name: 'AES-GCM', iv: iv }
            );
            return {
                wrappedKey: this._toBase64(new Uint8Array(wrapped)),
                wrapIv: this._toBase64(iv),
            };
        },

        unwrapFileKey: async function (wrappedB64, wrapIvB64) {
            var wrapped = this._fromBase64(wrappedB64);
            var iv = this._fromBase64(wrapIvB64);
            return crypto.subtle.unwrapKey(
                'raw', wrapped, this.masterKey, { name: 'AES-GCM', iv: iv },
                { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
        },

        _toBase64: function (bytes) {
            var binary = '';
            for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
            return btoa(binary);
        },

        _fromBase64: function (b64) {
            var binary = atob(b64);
            var bytes = new Uint8Array(binary.length);
            for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            return bytes;
        },
    };


    // ── Password Strength ──

    function checkPasswordStrength(password) {
        var score = 0;
        if (password.length >= 8) score++;
        if (password.length >= 12) score++;
        if (password.length >= 16) score++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[^a-zA-Z0-9]/.test(password)) score++;
        if (/(.)\1{2,}/.test(password)) score--;
        if (/^(123|abc|qwerty|password)/i.test(password)) score -= 2;
        score = Math.max(0, Math.min(5, score));

        var labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
        var classes = ['very-weak', 'weak', 'fair', 'good', 'strong', 'excellent'];
        return { score: score, label: labels[score], cls: classes[score] };
    }


    // ── Auth Page ──

    var Auth = {
        mode: 'login',
        pendingTempToken: null,

        init: function () {
            var self = this;
            $$('.auth-tab').forEach(function (tab) {
                tab.addEventListener('click', function () {
                    self.setMode(tab.dataset.tab);
                });
            });
            $('#auth-form').addEventListener('submit', function (e) {
                e.preventDefault();
                self.submit();
            });
            var pw = $('#password');
            if (pw) {
                pw.addEventListener('input', function () { self.updateStrength(); });
            }
        },
        setMode: function (mode) {
            this.mode = mode;
            this.pendingTempToken = null;
            $$('.auth-tab').forEach(function (t) { t.classList.toggle('active', t.dataset.tab === mode); });
            var cg = $('#confirm-group');
            var cp = $('#confirm-password');
            var sg = $('#strength-group');
            var tg = $('#totp-group');
            if (mode === 'register') {
                cg.style.display = '';
                cp.required = true;
                if (sg) sg.style.display = '';
                if (tg) tg.style.display = 'none';
                $('.btn-text').textContent = 'Create Account';
            } else {
                cg.style.display = 'none';
                cp.required = false;
                if (sg) sg.style.display = 'none';
                if (tg) tg.style.display = 'none';
                $('.btn-text').textContent = 'Sign In';
            }
            $('#auth-error').style.display = 'none';
            this.updateStrength();
        },
        updateStrength: function () {
            var meter = $('#strength-fill');
            var label = $('#strength-label');
            if (!meter || !label) return;
            if (this.mode !== 'register') return;
            var pw = $('#password').value;
            if (!pw) {
                meter.style.width = '0%';
                meter.className = 'strength-fill';
                label.textContent = '';
                return;
            }
            var s = checkPasswordStrength(pw);
            meter.style.width = ((s.score + 1) / 6 * 100) + '%';
            meter.className = 'strength-fill ' + s.cls;
            label.textContent = s.label;
            label.className = 'strength-label ' + s.cls;
        },
        submit: async function () {
            var self = this;
            var errorEl = $('#auth-error');
            errorEl.style.display = 'none';

            // Handle 2FA validation
            if (this.pendingTempToken) {
                var code = ($('#totp-code') || {}).value || '';
                if (!code || code.length !== 6) {
                    errorEl.textContent = 'Enter a valid 6-digit code';
                    errorEl.style.display = '';
                    return;
                }
                var btn = $('#auth-submit');
                btn.disabled = true;
                $('.btn-text').style.display = 'none';
                $('.btn-loader').style.display = '';

                try {
                    var result = await api('/api/auth/2fa/validate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ temp_token: this.pendingTempToken, code: code }),
                    });
                    if (result && result.success) {
                        if (result.master_key) {
                            await CryptoModule.setMasterKey(result.master_key);
                        }
                        window.location.href = '/vault';
                    } else {
                        errorEl.textContent = (result && result.error) || '2FA verification failed';
                        errorEl.style.display = '';
                    }
                } catch (err) {
                    errorEl.textContent = 'Connection error';
                    errorEl.style.display = '';
                }

                btn.disabled = false;
                $('.btn-text').style.display = '';
                $('.btn-loader').style.display = 'none';
                return;
            }

            var username = $('#username').value.trim();
            var password = $('#password').value;

            if (this.mode === 'register') {
                var confirm = $('#confirm-password').value;
                if (password !== confirm) {
                    errorEl.textContent = 'Passwords do not match';
                    errorEl.style.display = '';
                    return;
                }
                if (password.length < 8) {
                    errorEl.textContent = 'Password must be at least 8 characters';
                    errorEl.style.display = '';
                    return;
                }
                var strength = checkPasswordStrength(password);
                if (strength.score < 2) {
                    errorEl.textContent = 'Password is too weak — add uppercase letters, numbers, or symbols';
                    errorEl.style.display = '';
                    return;
                }
            }

            var btn = $('#auth-submit');
            btn.disabled = true;
            $('.btn-text').style.display = 'none';
            $('.btn-loader').style.display = '';

            try {
                var preAuthKey = await hashPassword(password, username);
                var endpoint = this.mode === 'register' ? '/api/auth/register' : '/api/auth/login';
                var result = await api(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username, pre_auth_key: preAuthKey }),
                });
                if (result && result.success) {
                    if (result.requires_2fa) {
                        // Show 2FA input
                        self.pendingTempToken = result.temp_token;
                        var tg = $('#totp-group');
                        if (tg) tg.style.display = '';
                        $('#username').disabled = true;
                        $('#password').disabled = true;
                        $('.btn-text').textContent = 'Verify Code';
                        setTimeout(function () {
                            var tc = $('#totp-code');
                            if (tc) tc.focus();
                        }, 100);
                    } else {
                        if (result.master_key) {
                            await CryptoModule.setMasterKey(result.master_key);
                        }
                        window.location.href = '/vault';
                    }
                } else {
                    errorEl.textContent = (result && result.error) || 'Authentication failed';
                    errorEl.style.display = '';
                }
            } catch (err) {
                errorEl.textContent = 'Connection error — please try again';
                errorEl.style.display = '';
            }

            btn.disabled = false;
            $('.btn-text').style.display = '';
            $('.btn-loader').style.display = 'none';
        },
    };


    // ── Session Timer ──

    var SessionTimer = {
        remaining: 3600,
        interval: null,
        warningShown: false,

        init: function () {
            var self = this;
            this.el = $('#session-timer');
            if (!this.el) return;
            this.refresh();
            this.interval = setInterval(function () { self.tick(); }, 1000);
            setInterval(function () { self.refresh(); }, 60000);
        },

        refresh: async function () {
            var result = await api('/api/auth/session');
            if (result && result.success) {
                this.remaining = result.remaining;
            }
        },

        tick: function () {
            this.remaining = Math.max(0, this.remaining - 1);
            if (this.el) {
                var m = Math.floor(this.remaining / 60);
                var s = this.remaining % 60;
                this.el.textContent = m + ':' + (s < 10 ? '0' : '') + s;
                if (this.remaining <= 300) {
                    this.el.classList.add('warning');
                } else {
                    this.el.classList.remove('warning');
                }
            }
            if (this.remaining <= 300 && !this.warningShown) {
                this.warningShown = true;
                toast('Session expires in 5 minutes', 'info');
            }
            if (this.remaining <= 0) {
                clearInterval(this.interval);
                toast('Session expired — redirecting to login', 'error');
                setTimeout(function () { window.location.href = '/auth'; }, 2000);
            }
        },
    };


    // ── Vault Dashboard ──

    var Vault = {
        files: [],
        shared: [],
        currentTab: 'vault',
        shareFileId: null,
        searchQuery: '',

        init: function () {
            this.bindTabs();
            this.bindUpload();
            this.bindLogout();
            this.bindShareModal();
            this.bindVersionModal();
            this.bindSearch();
            this.bind2FA();
            this.loadFiles();
            this.loadShared();
            SessionTimer.init();
        },

        bindTabs: function () {
            var self = this;
            $$('.nav-tab[data-tab]').forEach(function (tab) {
                tab.addEventListener('click', function (e) {
                    e.preventDefault();
                    self.switchTab(tab.dataset.tab);
                });
            });
        },

        switchTab: function (tab) {
            this.currentTab = tab;
            $$('.nav-tab[data-tab]').forEach(function (t) { t.classList.toggle('active', t.dataset.tab === tab); });
            $$('.tab-panel').forEach(function (p) { p.classList.toggle('active', p.id === tab + '-tab'); });
        },

        // ── Search ──

        bindSearch: function () {
            var self = this;
            var input = $('#file-search');
            if (!input) return;
            input.addEventListener('input', function () {
                self.searchQuery = input.value.trim().toLowerCase();
                self.renderFiles();
            });
        },

        // ── Upload ──

        bindUpload: function () {
            var self = this;
            var zone = $('#upload-zone');
            var input = $('#file-input');
            if (!zone || !input) return;

            zone.addEventListener('click', function () { input.click(); });
            input.addEventListener('change', function () {
                if (input.files.length) self.uploadFiles(input.files);
                input.value = '';
            });

            zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('dragover'); });
            zone.addEventListener('dragleave', function () { zone.classList.remove('dragover'); });
            zone.addEventListener('drop', function (e) {
                e.preventDefault();
                zone.classList.remove('dragover');
                if (e.dataTransfer.files.length) self.uploadFiles(e.dataTransfer.files);
            });
        },

        uploadFiles: async function (fileList) {
            var maxSize = 100 * 1024 * 1024;
            var prog = $('#upload-progress');
            var fill = $('#progress-fill');
            var text = $('#progress-text');
            prog.style.display = '';

            var total = fileList.length;
            var uploaded = 0;

            for (var i = 0; i < fileList.length; i++) {
                var file = fileList[i];

                if (file.size > maxSize) {
                    toast(file.name + ' exceeds 100 MB limit', 'error');
                    uploaded++;
                    continue;
                }

                if (file.size === 0) {
                    toast(file.name + ' is empty', 'error');
                    uploaded++;
                    continue;
                }

                text.textContent = 'Encrypting ' + file.name + '...';
                fill.style.width = ((uploaded / total) * 100) + '%';

                var fd = new FormData();
                fd.append('file', file);
                try {
                    var result = await api('/api/vault/upload', { method: 'POST', body: fd });
                    if (result && result.success) {
                        toast(file.name + ' encrypted and stored', 'success');
                    } else {
                        toast((result && result.error) || 'Upload failed', 'error');
                    }
                } catch (err) {
                    toast('Upload failed: ' + file.name, 'error');
                }
                uploaded++;
            }

            fill.style.width = '100%';
            text.textContent = 'Complete';
            setTimeout(function () { prog.style.display = 'none'; fill.style.width = '0%'; }, 1500);
            this.loadFiles();
        },

        loadFiles: async function () {
            var result = await api('/api/vault/files');
            if (!result || !result.success) return;
            this.files = result.files;
            this.renderFiles();
        },

        renderFiles: function () {
            var list = $('#file-list');
            var empty = $('#empty-state');
            var table = $('#file-table');
            var count = $('#file-count');
            if (!list) return;

            var filtered = this.files;
            if (this.searchQuery) {
                var q = this.searchQuery;
                filtered = this.files.filter(function (f) {
                    return f.filename.toLowerCase().indexOf(q) !== -1;
                });
            }

            count.textContent = filtered.length + ' file' + (filtered.length !== 1 ? 's' : '');

            if (filtered.length === 0) {
                table.style.display = 'none';
                empty.style.display = '';
                if (this.searchQuery && this.files.length > 0) {
                    empty.querySelector('p').textContent = 'No files match your search';
                    empty.querySelector('span').textContent = 'Try a different search term';
                } else {
                    empty.querySelector('p').textContent = 'No files yet';
                    empty.querySelector('span').textContent = 'Upload files to get started';
                }
                return;
            }

            table.style.display = '';
            empty.style.display = 'none';
            var self = this;
            list.innerHTML = filtered.map(function (f) {
                var ft = fileTypeInfo(f.filename);
                return '<tr>' +
                    '<td><div class="file-name"><div class="file-icon ' + ft.cls + '">' + ft.label + '</div>' + escapeHtml(f.filename) + '</div></td>' +
                    '<td class="file-size">' + formatSize(f.size) + '</td>' +
                    '<td><span class="version-badge" data-id="' + f.id + '">v' + f.current_version + '</span></td>' +
                    '<td class="file-date">' + formatDate(f.updated_at) + '</td>' +
                    '<td class="file-actions">' +
                        '<button class="btn-icon" title="Download" data-action="download" data-id="' + f.id + '">' +
                            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>' +
                        '</button>' +
                        '<button class="btn-icon" title="Share" data-action="share" data-id="' + f.id + '" data-name="' + escapeAttr(f.filename) + '">' +
                            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>' +
                        '</button>' +
                        '<button class="btn-icon danger" title="Delete" data-action="delete" data-id="' + f.id + '" data-name="' + escapeAttr(f.filename) + '">' +
                            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg>' +
                        '</button>' +
                    '</td></tr>';
            }).join('');

            list.querySelectorAll('[data-action]').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var action = btn.dataset.action;
                    var id = btn.dataset.id;
                    if (action === 'download') self.downloadFile(id);
                    else if (action === 'share') self.openShareModal(id, btn.dataset.name);
                    else if (action === 'delete') self.deleteFile(id, btn.dataset.name);
                });
            });

            list.querySelectorAll('.version-badge').forEach(function (badge) {
                badge.addEventListener('click', function () {
                    var file = self.files.find(function (f) { return f.id === badge.dataset.id; });
                    if (file) self.openVersionModal(file);
                });
            });
        },

        downloadFile: function (fileId) {
            window.location.href = '/api/vault/files/' + fileId + '/download';
        },

        deleteFile: async function (fileId, name) {
            if (!confirm('Delete "' + name + '"? This cannot be undone.')) return;
            var result = await api('/api/vault/files/' + fileId, { method: 'DELETE' });
            if (result && result.success) {
                toast(name + ' deleted', 'success');
                this.loadFiles();
            } else {
                toast((result && result.error) || 'Delete failed', 'error');
            }
        },

        // ── Share Modal ──

        bindShareModal: function () {
            var self = this;
            var modal = $('#share-modal');
            if (!modal) return;
            $('#share-close').addEventListener('click', function () { modal.style.display = 'none'; });
            $('#share-cancel').addEventListener('click', function () { modal.style.display = 'none'; });
            $('#share-confirm').addEventListener('click', function () { self.submitShare(); });
            modal.addEventListener('click', function (e) { if (e.target === modal) modal.style.display = 'none'; });
            $('#share-recipient').addEventListener('keydown', function (e) { if (e.key === 'Enter') self.submitShare(); });
        },

        openShareModal: function (fileId, filename) {
            this.shareFileId = fileId;
            $('#share-filename').textContent = filename;
            $('#share-recipient').value = '';
            $('#share-error').style.display = 'none';
            $('#share-modal').style.display = '';
            $('#share-recipient').focus();
        },

        submitShare: async function () {
            var recipient = $('#share-recipient').value.trim();
            var errorEl = $('#share-error');
            if (!recipient) {
                errorEl.textContent = 'Enter a recipient username';
                errorEl.style.display = '';
                return;
            }
            errorEl.style.display = 'none';
            var btn = $('#share-confirm');
            btn.disabled = true;
            btn.textContent = 'Sharing...';

            var result = await api('/api/vault/files/' + this.shareFileId + '/share', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient: recipient }),
            });
            if (result && result.success) {
                toast('File shared with ' + recipient, 'success');
                $('#share-modal').style.display = 'none';
            } else {
                errorEl.textContent = (result && result.error) || 'Share failed';
                errorEl.style.display = '';
            }
            btn.disabled = false;
            btn.textContent = 'Share';
        },

        // ── Version Modal ──

        bindVersionModal: function () {
            var modal = $('#version-modal');
            if (!modal) return;
            $('#version-close').addEventListener('click', function () { modal.style.display = 'none'; });
            modal.addEventListener('click', function (e) { if (e.target === modal) modal.style.display = 'none'; });
        },

        openVersionModal: function (file) {
            $('#version-filename').textContent = file.filename;
            var list = $('#version-list');
            list.innerHTML = file.versions.map(function (v) {
                var current = v.version === file.current_version ? '<span class="version-current">current</span>' : '';
                return '<div class="version-item">' +
                    '<div class="version-info">' +
                        '<span class="version-label">Version ' + v.version + current + '</span>' +
                        '<span class="version-meta">' + formatSize(v.size) + ' &middot; ' + formatDate(v.created_at) + '</span>' +
                    '</div>' +
                    '<button class="btn btn-ghost btn-sm" onclick="window.location.href=\'/api/vault/files/' + file.id + '/download/' + v.version + '\'">Download</button>' +
                '</div>';
            }).join('');
            $('#version-modal').style.display = '';
        },

        // ── 2FA Modal ──

        bind2FA: function () {
            var self = this;
            var btn = $('#2fa-toggle-btn');
            var modal = $('#2fa-modal');
            if (!btn || !modal) return;

            btn.addEventListener('click', function () { self.open2FAModal(); });
            $('#2fa-close').addEventListener('click', function () { modal.style.display = 'none'; });
            $('#2fa-cancel').addEventListener('click', function () { modal.style.display = 'none'; });
            $('#2fa-disable-cancel').addEventListener('click', function () { modal.style.display = 'none'; });
            modal.addEventListener('click', function (e) { if (e.target === modal) modal.style.display = 'none'; });

            $('#2fa-verify-btn').addEventListener('click', function () { self.verify2FA(); });
            $('#2fa-disable-btn').addEventListener('click', function () { self.disable2FA(); });
        },

        open2FAModal: async function () {
            var modal = $('#2fa-modal');
            var setupView = $('#2fa-setup-view');
            var disableView = $('#2fa-disable-view');

            // Try to setup — if 2FA already enabled, it returns an error and we show disable view
            var result = await api('/api/auth/2fa/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}),
            });

            if (result && result.success) {
                // Show setup view
                $('#2fa-modal-title').textContent = 'Enable Two-Factor Authentication';
                setupView.style.display = '';
                disableView.style.display = 'none';
                $('#2fa-secret').textContent = result.secret;
                $('#2fa-verify-code').value = '';
                $('#2fa-error').style.display = 'none';
            } else if (result && result.error && result.error.includes('already enabled')) {
                // Show disable view
                $('#2fa-modal-title').textContent = 'Disable Two-Factor Authentication';
                setupView.style.display = 'none';
                disableView.style.display = '';
                $('#2fa-disable-code').value = '';
                $('#2fa-disable-error').style.display = 'none';
            } else {
                toast((result && result.error) || '2FA not available', 'error');
                return;
            }

            modal.style.display = '';
        },

        verify2FA: async function () {
            var code = ($('#2fa-verify-code') || {}).value || '';
            var errorEl = $('#2fa-error');
            if (!code || code.length !== 6) {
                errorEl.textContent = 'Enter a valid 6-digit code';
                errorEl.style.display = '';
                return;
            }
            errorEl.style.display = 'none';

            var result = await api('/api/auth/2fa/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: code }),
            });

            if (result && result.success) {
                toast('Two-factor authentication enabled', 'success');
                $('#2fa-modal').style.display = 'none';
            } else {
                errorEl.textContent = (result && result.error) || 'Verification failed';
                errorEl.style.display = '';
            }
        },

        disable2FA: async function () {
            var code = ($('#2fa-disable-code') || {}).value || '';
            var errorEl = $('#2fa-disable-error');
            if (!code || code.length !== 6) {
                errorEl.textContent = 'Enter a valid 6-digit code';
                errorEl.style.display = '';
                return;
            }
            errorEl.style.display = 'none';

            var result = await api('/api/auth/2fa/disable', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: code }),
            });

            if (result && result.success) {
                toast('Two-factor authentication disabled', 'success');
                $('#2fa-modal').style.display = 'none';
            } else {
                errorEl.textContent = (result && result.error) || 'Disable failed';
                errorEl.style.display = '';
            }
        },

        // ── Shared Files ──

        loadShared: async function () {
            var result = await api('/api/vault/shared');
            if (!result || !result.success) return;
            this.shared = result.shared_files;
            this.renderShared();
        },

        renderShared: function () {
            var list = $('#shared-list');
            var empty = $('#shared-empty');
            var table = $('#shared-table');
            var count = $('#shared-count');
            if (!list) return;

            count.textContent = this.shared.length + ' file' + (this.shared.length !== 1 ? 's' : '');

            if (this.shared.length === 0) {
                table.style.display = 'none';
                empty.style.display = '';
                return;
            }

            table.style.display = '';
            empty.style.display = 'none';
            list.innerHTML = this.shared.map(function (s) {
                var ft = fileTypeInfo(s.filename);
                var dlBtn = s.available
                    ? '<button class="btn-icon" title="Download" onclick="window.location.href=\'/api/vault/shared/' + s.share_id + '/download\'"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></button>'
                    : '<span class="file-unavailable">Unavailable</span>';
                return '<tr>' +
                    '<td><div class="file-name"><div class="file-icon ' + ft.cls + '">' + ft.label + '</div>' + escapeHtml(s.filename) + '</div></td>' +
                    '<td class="sender-badge">' + escapeHtml(s.sender) + '</td>' +
                    '<td class="file-size">' + formatSize(s.size) + '</td>' +
                    '<td class="file-date">' + formatDate(s.shared_at) + '</td>' +
                    '<td class="file-actions">' + dlBtn + '</td></tr>';
            }).join('');
        },

        // ── Logout ──

        bindLogout: function () {
            var btn = $('#logout-btn');
            if (!btn) return;
            btn.addEventListener('click', async function () {
                await api('/api/auth/logout', { method: 'POST' });
                CryptoModule.masterKey = null;
                window.location.href = '/auth';
            });
        },
    };


    // ── Audit Page ──

    var Audit = {
        logs: [],
        init: function () {
            this.loadLogs();
            this.bindFilter();
            this.bindLogout();
            SessionTimer.init();
        },
        bindLogout: function () {
            var btn = $('#logout-btn');
            if (!btn) return;
            btn.addEventListener('click', async function () {
                await api('/api/auth/logout', { method: 'POST' });
                CryptoModule.masterKey = null;
                window.location.href = '/auth';
            });
        },
        bindFilter: function () {
            var self = this;
            var filter = $('#audit-filter');
            if (!filter) return;
            filter.addEventListener('change', function () { self.renderLogs(); });
        },
        loadLogs: async function () {
            var result = await api('/api/vault/audit');
            if (!result || !result.success) return;
            this.logs = result.logs;
            this.renderLogs();
        },
        renderLogs: function () {
            var list = $('#audit-list');
            var empty = $('#audit-empty');
            var filter = ($('#audit-filter') || {}).value || '';
            if (!list) return;

            var filtered = filter ? this.logs.filter(function (l) { return l.action === filter; }) : this.logs;

            if (filtered.length === 0) {
                list.innerHTML = '';
                empty.style.display = '';
                return;
            }
            empty.style.display = 'none';

            list.innerHTML = filtered.map(function (l) {
                var actionLabel = l.action.replace(/_/g, ' ');
                return '<tr>' +
                    '<td class="file-date">' + formatDate(l.timestamp) + '</td>' +
                    '<td><span class="action-badge ' + l.action + '">' + actionLabel + '</span></td>' +
                    '<td>' + escapeHtml(l.filename || '') + '</td>' +
                    '<td style="color:var(--text-secondary)">' + escapeHtml(l.details) + '</td>' +
                    '<td class="audit-ip">' + escapeHtml(l.ip_address) + '</td></tr>';
            }).join('');
        },
    };

    function escapeHtml(s) {
        if (!s) return '';
        var div = document.createElement('div');
        div.textContent = s;
        return div.innerHTML;
    }

    function escapeAttr(s) {
        return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;');
    }

    document.addEventListener('DOMContentLoaded', function () {
        if ($('#auth-form')) Auth.init();
        else if ($('#vault-container')) Vault.init();
        else if ($('#audit-container')) Audit.init();
    });

})();

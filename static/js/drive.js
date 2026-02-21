/* BlindBit SSE — Drive (Files) JS */

function getCSRF() {
    const c = document.cookie.match(/csrftoken=([^;]+)/);
    if (c) return c[1];
    const el = document.querySelector('[name=csrfmiddlewaretoken]');
    return el ? el.value : '';
}

async function uploadFile(input) {
    const popup = window.BlindBitPopup;
    const file = input.files[0];
    if (!file) return;
    const wantsSecretKeyword = await popup.confirm(
        'Do you want to add a custom secret keyword for this file?',
        { title: 'Secret Keyword', confirmText: 'Add Keyword' }
    );
    let manualKeyword = '';
    if (wantsSecretKeyword) {
        const val = await popup.prompt(
            'Enter a secret keyword (or multiple words). It will be searchable even if not present in the file.',
            { title: 'Secret Keyword Input', confirmText: 'Use Keyword', placeholder: 'e.g. project-orchid' }
        );
        manualKeyword = (val || '').trim();
    }

    const status = document.getElementById('upload-status');
    const result = document.getElementById('upload-result');
    status.style.display = 'flex';
    result.style.display = 'none';
    document.getElementById('upload-msg').textContent = `Encrypting ${file.name}...`;

    const fd = new FormData();
    fd.append('file', file);
    if (manualKeyword) {
        fd.append('manual_keyword', manualKeyword);
    }

    try {
        const res = await fetch('/upload/', {
            method: 'POST',
            headers: { 'X-CSRFToken': getCSRF() },
            body: fd
        });
        const d = await res.json();
        status.style.display = 'none';

        if (d.error) {
            await popup.alert(d.error, { title: 'Upload Failed', tone: 'red' });
            return;
        }

        result.style.display = 'block';
        document.getElementById('upload-details').innerHTML = `
            <div class="upload-success-grid">
                <div><strong>File:</strong> ${d.filename}</div>
                <div><strong>File ID:</strong> <code>${d.file_id.substring(0, 24)}...</code></div>
                <div><strong>Keywords:</strong> ${d.keywords}</div>
                ${d.secret_keywords_added && d.secret_keywords_added.length ? `<div><strong>Secret keyword(s):</strong> ${d.secret_keywords_added.join(', ')}</div>` : ''}
                <div><strong>Tokens:</strong> K=${d.tokens.K}, N=${d.tokens.N}, B=${d.tokens.B} (total: ${d.tokens.total})</div>
                <div><strong>Encrypt time:</strong> ${d.encrypt_time}s</div>
                <div><strong>Index time:</strong> ${d.index_time}s</div>
                <div><strong>Encrypted size:</strong> ${(d.size / 1024).toFixed(1)} KB</div>
            </div>
            ${d.tfidf_top.length ? `<div class="tfidf-chips">${d.tfidf_top.map(t => `<span class="kw-chip">${t.keyword} (${t.score})</span>`).join('')}</div>` : ''}
        `;
        // Reload after 2s to show new file
        setTimeout(() => location.reload(), 2000);
    } catch (e) {
        status.style.display = 'none';
        await popup.alert('Upload failed: ' + e.message, { title: 'Upload Failed', tone: 'red' });
    }
    input.value = '';
}

async function deleteFile(fid) {
    const popup = window.BlindBitPopup;
    const confirmed = await popup.confirm('Delete this encrypted file?', {
        title: 'Delete File',
        tone: 'red',
        confirmText: 'Delete',
    });
    if (!confirmed) return;
    try {
        const res = await fetch(`/delete-file/${fid}/`, {
            method: 'POST',
            headers: { 'X-CSRFToken': getCSRF() }
        });
        const d = await res.json();
        if (!res.ok || d.error) {
            await popup.alert(d.error || 'Delete failed', { title: 'Delete Failed', tone: 'red' });
            return;
        }
        const el = document.getElementById('file-' + fid);
        if (el) {
            el.style.opacity = '0';
            el.style.transform = 'scale(0.95)';
            setTimeout(() => el.remove(), 300);
        }
    } catch (e) {
        await popup.alert('Delete failed: ' + e.message, { title: 'Delete Failed', tone: 'red' });
    }
}

async function viewRecord(rid) {
    const popup = window.BlindBitPopup;
    try {
        const res = await fetch(`/records/view/${rid}/`);
        const d = await res.json();
        if (!res.ok || d.error) {
            await popup.alert(d.error || 'Failed to view record', { title: 'View Failed', tone: 'red' });
            return;
        }
        document.getElementById('record-content').textContent = d.content;
        document.getElementById('record-modal').style.display = 'flex';
    } catch (e) {
        await popup.alert('Failed to view record: ' + e.message, { title: 'View Failed', tone: 'red' });
    }
}

async function deleteRecord(rid) {
    const popup = window.BlindBitPopup;
    const confirmed = await popup.confirm('Delete this record?', {
        title: 'Delete Record',
        tone: 'red',
        confirmText: 'Delete',
    });
    if (!confirmed) return;
    try {
        const res = await fetch(`/records/delete/${rid}/`, {
            method: 'POST',
            headers: { 'X-CSRFToken': getCSRF() }
        });
        const d = await res.json();
        if (!res.ok || d.error) {
            await popup.alert(d.error || 'Delete failed', { title: 'Delete Failed', tone: 'red' });
            return;
        }
        const el = document.getElementById('rec-' + rid);
        if (el) {
            el.style.opacity = '0';
            setTimeout(() => el.remove(), 300);
        }
    } catch (e) {
        await popup.alert('Delete failed: ' + e.message, { title: 'Delete Failed', tone: 'red' });
    }
}

function closeModal() {
    document.getElementById('record-modal').style.display = 'none';
}

/* -----------------------------------------------------------------------
   File Sharing
   ----------------------------------------------------------------------- */

function openShareModal(fileId, filename) {
    document.getElementById('share-file-id').value = fileId;
    document.getElementById('share-filename').textContent = `Sharing: ${filename}`;
    document.getElementById('share-username').value = '';
    const statusEl = document.getElementById('share-status');
    statusEl.style.display = 'none';
    statusEl.textContent = '';
    document.getElementById('share-modal').style.display = 'flex';
    loadShareList(fileId);
}

function closeShareModal() {
    document.getElementById('share-modal').style.display = 'none';
}

async function submitShare() {
    const popup = window.BlindBitPopup;
    const fileId = document.getElementById('share-file-id').value;
    const username = document.getElementById('share-username').value.trim();
    const statusEl = document.getElementById('share-status');
    const btn = document.getElementById('share-submit-btn');

    if (!username) {
        statusEl.style.display = 'block';
        statusEl.style.background = 'var(--error-soft, #fde8e8)';
        statusEl.style.color = 'var(--error, #c0392b)';
        statusEl.textContent = 'Please enter a username.';
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Sharing...';
    statusEl.style.display = 'none';

    try {
        const res = await fetch('/api/share/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRF(),
            },
            body: JSON.stringify({
                file_id: fileId,
                target_username: username,
            }),
        });
        const d = await res.json();
        if (!res.ok || d.error) {
            statusEl.style.display = 'block';
            statusEl.style.background = 'var(--error-soft, #fde8e8)';
            statusEl.style.color = 'var(--error, #c0392b)';
            statusEl.textContent = d.error || 'Share failed';
        } else {
            statusEl.style.display = 'block';
            statusEl.style.background = 'var(--green-soft, #e8f8e8)';
            statusEl.style.color = 'var(--green-dark, #27ae60)';
            statusEl.textContent = `File shared with ${username}!`;
            document.getElementById('share-username').value = '';
            loadShareList(fileId);
        }
    } catch (e) {
        statusEl.style.display = 'block';
        statusEl.style.background = 'var(--error-soft, #fde8e8)';
        statusEl.style.color = 'var(--error, #c0392b)';
        statusEl.textContent = 'Network error: ' + e.message;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Share';
    }
}

async function loadShareList(fileId) {
    const section = document.getElementById('share-list-section');
    const listEl = document.getElementById('share-list');

    try {
        const res = await fetch(`/api/files/${fileId}/shares/`);
        const d = await res.json();
        if (!res.ok || !d.shares) {
            section.style.display = 'none';
            return;
        }
        if (d.shares.length === 0) {
            section.style.display = 'none';
            return;
        }
        section.style.display = 'block';
        listEl.innerHTML = d.shares.map(s =>
            `<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);">
                <span>${s.username} <span style="opacity:.5;font-size:12px;">· ${new Date(s.shared_at).toLocaleDateString()}</span></span>
                <button class="btn btn-sm btn-ghost" style="border-color:var(--error);color:var(--error);font-size:11px;padding:2px 8px;"
                    onclick="revokeShare('${fileId}', '${s.username}')">Revoke</button>
            </div>`
        ).join('');
    } catch {
        section.style.display = 'none';
    }
}

async function revokeShare(fileId, username) {
    const popup = window.BlindBitPopup;
    const confirmed = await popup.confirm(`Revoke access for ${username}?`, {
        title: 'Revoke Share',
        tone: 'red',
        confirmText: 'Revoke',
    });
    if (!confirmed) return;
    try {
        const res = await fetch(`/api/share/${fileId}/revoke/${username}/`, {
            method: 'POST',
            headers: { 'X-CSRFToken': getCSRF() },
        });
        const d = await res.json();
        if (!res.ok || d.error) {
            await popup.alert(d.error || 'Revoke failed', { title: 'Revoke Failed', tone: 'red' });
            return;
        }
        loadShareList(fileId);
    } catch (e) {
        await popup.alert('Revoke failed: ' + e.message, { title: 'Revoke Failed', tone: 'red' });
    }
}

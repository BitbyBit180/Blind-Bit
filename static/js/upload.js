function getCSRF() {
    const c = document.cookie.match(/csrftoken=([^;]+)/);
    if (c) return c[1];
    const el = document.querySelector('[name=csrfmiddlewaretoken]');
    return el ? el.value : '';
}

document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('upload-file-input');
    const fileName = document.getElementById('upload-file-name');
    if (!fileInput || !fileName) return;
    fileInput.addEventListener('change', () => {
        fileName.textContent = fileInput.files[0] ? fileInput.files[0].name : 'No file selected';
    });
});

async function submitUpload() {
    const popup = window.BlindBitPopup;
    const fileInput = document.getElementById('upload-file-input');
    const keywordInput = document.getElementById('manual-keyword-input');
    const file = fileInput.files[0];
    const manualKeyword = (keywordInput.value || '').trim();

    if (!file) {
        await popup.alert('Please choose a file to upload.', { title: 'File Required' });
        return;
    }

    const status = document.getElementById('upload-status');
    const result = document.getElementById('upload-result');
    status.style.display = 'block';
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

        let d;
        try {
            d = await res.json();
        } catch (parseErr) {
            status.style.display = 'none';
            await popup.alert(
                `Server returned status ${res.status} but the response could not be parsed. The file may have been uploaded — check My Files.`,
                { title: 'Upload Response Error', tone: 'red' }
            );
            return;
        }

        status.style.display = 'none';

        if (!res.ok || d.error) {
            await popup.alert(d.error || 'Upload failed', { title: 'Upload Failed', tone: 'red' });
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

        fileInput.value = '';
        keywordInput.value = '';
        const fileName = document.getElementById('upload-file-name');
        if (fileName) fileName.textContent = 'No file selected';
    } catch (e) {
        status.style.display = 'none';
        await popup.alert('Upload failed: ' + e.message, { title: 'Upload Failed', tone: 'red' });
    }
}

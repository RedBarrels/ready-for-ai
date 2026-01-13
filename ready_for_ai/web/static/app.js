// Ready for AI - Web Interface

// State
let currentSessionId = null;
let hasFile = false;

// DOM Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const selectedFile = document.getElementById('selected-file');
const inputText = document.getElementById('input-text');
const redactBtn = document.getElementById('redact-btn');
const outputPlaceholder = document.getElementById('output-placeholder');
const outputText = document.getElementById('output-text');
const outputActions = document.getElementById('output-actions');
const copyBtn = document.getElementById('copy-btn');
const downloadBtn = document.getElementById('download-btn');
const statsBadge = document.getElementById('stats-badge');
const aiResponseInput = document.getElementById('ai-response-input');
const restoredOutput = document.getElementById('restored-output');
const restoreBtn = document.getElementById('restore-btn');
const copyRestoredBtn = document.getElementById('copy-restored-btn');
const restoreStatus = document.getElementById('restore-status');
const loadingOverlay = document.getElementById('loading-overlay');
const toast = document.getElementById('toast');
const themeToggle = document.getElementById('theme-toggle');

// Theme handling
function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
        document.documentElement.classList.add('dark');
    }
}

function toggleTheme() {
    document.documentElement.classList.toggle('dark');
    const isDark = document.documentElement.classList.contains('dark');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
}

// Toast notifications
function showToast(message, type = 'info') {
    toast.textContent = message;
    toast.className = `fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg transition-all transform ${type}`;

    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);

    // Hide after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// Loading state
function showLoading() {
    loadingOverlay.classList.remove('hidden');
}

function hideLoading() {
    loadingOverlay.classList.add('hidden');
}

// File handling
function handleFileSelect(file) {
    if (!file) return;

    const validExtensions = ['.docx', '.pdf', '.txt', '.md', '.markdown', '.text', '.xlsx', '.xlsm', '.pptx'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();

    if (!validExtensions.includes(ext)) {
        showToast('Unsupported file type', 'error');
        return;
    }

    selectedFile.textContent = file.name;
    selectedFile.classList.remove('hidden');
    inputText.value = '';
    inputText.disabled = true;
    inputText.placeholder = 'File selected - clear file to paste text';
}

function clearFile() {
    fileInput.value = '';
    selectedFile.classList.add('hidden');
    selectedFile.textContent = '';
    inputText.disabled = false;
    inputText.placeholder = 'Paste your text here...';
}

// Drag and drop
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');

    const file = e.dataTransfer.files[0];
    if (file) {
        handleFileSelect(file);
        // Create a DataTransfer to set the file input
        const dt = new DataTransfer();
        dt.items.add(file);
        fileInput.files = dt.files;
    }
});

fileInput.addEventListener('change', (e) => {
    handleFileSelect(e.target.files[0]);
});

// Double-click to clear file
selectedFile.addEventListener('dblclick', clearFile);

// Redact
async function redact() {
    const file = fileInput.files[0];
    const text = inputText.value.trim();

    if (!file && !text) {
        showToast('Please upload a file or paste text', 'error');
        return;
    }

    showLoading();

    try {
        let response;

        if (file) {
            const formData = new FormData();
            formData.append('file', file);

            response = await fetch('/api/redact', {
                method: 'POST',
                body: formData,
            });
        } else {
            response = await fetch('/api/redact', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text }),
            });
        }

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Redaction failed');
        }

        // Update state
        currentSessionId = data.session_id;
        hasFile = data.has_file;

        // Update UI
        outputPlaceholder.classList.add('hidden');
        outputText.classList.remove('hidden');
        outputText.value = data.redacted_text || '(File processed - download to view)';
        outputActions.classList.remove('hidden');

        // Show/hide download button
        if (hasFile) {
            downloadBtn.classList.remove('hidden');
        } else {
            downloadBtn.classList.add('hidden');
        }

        // Update stats badge
        const stats = data.stats;
        if (stats.total_redactions > 0) {
            statsBadge.textContent = `${stats.total_redactions} redacted`;
            statsBadge.classList.remove('hidden');
        } else {
            statsBadge.textContent = 'No PII found';
            statsBadge.classList.remove('hidden');
        }

        // Enable restore section
        restoreBtn.disabled = false;

        showToast(`Redacted ${stats.total_redactions} items`, 'success');

    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        hideLoading();
    }
}

// Restore
async function restore() {
    const text = aiResponseInput.value.trim();

    if (!text) {
        showToast('Please paste the AI response', 'error');
        return;
    }

    if (!currentSessionId) {
        showToast('Please redact a document first', 'error');
        return;
    }

    showLoading();

    try {
        const response = await fetch('/api/restore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: currentSessionId,
                text: text,
            }),
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Restoration failed');
        }

        // Update UI
        restoredOutput.value = data.restored_text;
        copyRestoredBtn.classList.remove('hidden');

        // Show status
        restoreStatus.textContent = `Restored ${data.restoration_count} placeholder(s)`;
        restoreStatus.classList.remove('hidden');

        showToast(`Restored ${data.restoration_count} items`, 'success');

    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        hideLoading();
    }
}

// Copy to clipboard
async function copyToClipboard(text, successMessage = 'Copied to clipboard') {
    try {
        await navigator.clipboard.writeText(text);
        showToast(successMessage, 'success');
    } catch (error) {
        showToast('Failed to copy', 'error');
    }
}

// Download file
function downloadFile() {
    if (!currentSessionId || !hasFile) return;

    window.location.href = `/api/download/${currentSessionId}`;
}

// Event listeners
themeToggle.addEventListener('click', toggleTheme);
redactBtn.addEventListener('click', redact);
restoreBtn.addEventListener('click', restore);

copyBtn.addEventListener('click', () => {
    copyToClipboard(outputText.value);
});

copyRestoredBtn.addEventListener('click', () => {
    copyToClipboard(restoredOutput.value);
});

downloadBtn.addEventListener('click', downloadFile);

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + Enter to redact
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        if (document.activeElement === inputText || document.activeElement === fileInput) {
            redact();
        } else if (document.activeElement === aiResponseInput) {
            restore();
        }
    }
});

// Clear session on page unload
window.addEventListener('beforeunload', () => {
    if (currentSessionId) {
        // Use sendBeacon for reliable cleanup
        navigator.sendBeacon(`/api/session/${currentSessionId}`, JSON.stringify({ _method: 'DELETE' }));
    }
});

// Initialize
initTheme();
restoreBtn.disabled = true;

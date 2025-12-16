/**
 * Secure File Share - Frontend JavaScript
 * Handles file upload/download, file listing, and UI interactions
 */

// Get CSRF token from meta tag
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

// ================== UPLOAD HANDLING ==================
document.getElementById('upload-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const form = e.target;
    const formData = new FormData(form);
    const uploadBtn = document.getElementById('upload-btn');
    const progressContainer = document.getElementById('upload-progress-container');
    const progressBar = document.getElementById('upload-progress');
    const uploadCard = document.getElementById('upload-card');
    
    // Validate password before upload
    const password = document.getElementById('password').value;
    const validation = validatePassword(password);
    if (!validation.valid) {
        showToast(validation.message, false);
        triggerShake(uploadCard);
        return;
    }
    
    // Show progress bar and disable button
    progressContainer.style.display = 'block';
    setButtonLoading(uploadBtn, true);
    
    // Use XMLHttpRequest for progress tracking
    const xhr = new XMLHttpRequest();
    
    xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressBar.style.width = percent + '%';
            progressBar.textContent = percent + '%';
            progressBar.setAttribute('aria-valuenow', percent);
        }
    });
    
    xhr.addEventListener('load', () => {
        setButtonLoading(uploadBtn, false);
        progressContainer.style.display = 'none';
        progressBar.style.width = '0%';
        
        try {
            const result = JSON.parse(xhr.responseText);
            showToast(result.message, result.success);
            
            if (result.success) {
                form.reset();
                resetPasswordStrength();
                loadFiles(); // Refresh file list
            } else {
                triggerShake(uploadCard);
            }
        } catch {
            showToast('❌ Unexpected server response.', false);
            triggerShake(uploadCard);
        }
    });
    
    xhr.addEventListener('error', () => {
        setButtonLoading(uploadBtn, false);
        progressContainer.style.display = 'none';
        showToast('❌ Upload failed. Please try again.', false);
        triggerShake(uploadCard);
    });
    
    xhr.open('POST', '/upload');
    xhr.setRequestHeader('X-CSRFToken', csrfToken);
    xhr.send(formData);
});

// ================== DOWNLOAD HANDLING ==================
document.getElementById('download-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const form = e.target;
    const formData = new FormData(form);
    const downloadBtn = document.getElementById('download-btn');
    
    setButtonLoading(downloadBtn, true);
    showToast('🔄 Preparing your download...', true);
    
    try {
        const response = await fetch('/download', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken
            },
            body: formData
        });
        
        const contentType = response.headers.get('content-type');
        
        if (contentType && contentType.includes('application/json')) {
            const result = await response.json();
            showToast(result.message, result.success);
        } else {
            // File blob received
            const blob = await response.blob();
            
            if (blob.size === 0) {
                showToast('❌ Empty file or error occurred.', false);
                return;
            }
            
            showToast('✅ File decrypted and downloading...', true);
            
            const filename = form.filename.value || 'downloaded_file';
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);
            form.reset();
        }
    } catch {
        showToast('❌ Download failed. Please check your inputs.', false);
    } finally {
        setButtonLoading(downloadBtn, false);
    }
});

// ================== FILE LISTING ==================
async function loadFiles() {
    const loadingEl = document.getElementById('files-loading');
    const emptyEl = document.getElementById('files-empty');
    const listEl = document.getElementById('files-list');
    const tbody = document.getElementById('files-tbody');
    
    loadingEl.style.display = 'block';
    emptyEl.style.display = 'none';
    listEl.style.display = 'none';
    
    try {
        const response = await fetch('/api/files', {
            headers: {
                'X-CSRFToken': csrfToken
            }
        });
        const result = await response.json();
        
        loadingEl.style.display = 'none';
        
        if (result.success && result.files.length > 0) {
            tbody.innerHTML = '';
            
            result.files.forEach(file => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>
                        <span class="file-name" role="button" tabindex="0" title="Click to fill download form">
                            📄 ${escapeHtml(file.name)}
                        </span>
                        <button class="btn btn-sm btn-link copy-btn" title="Copy filename" aria-label="Copy filename">
                            📋
                        </button>
                    </td>
                    <td>${formatFileSize(file.size)}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger delete-btn" data-filename="${escapeHtml(file.name)}" aria-label="Delete file">
                            🗑️ Delete
                        </button>
                    </td>
                `;
                
                // Click filename to fill download form
                row.querySelector('.file-name').addEventListener('click', () => {
                    document.getElementById('filename').value = file.name;
                    document.getElementById('password_dl').focus();
                    showToast('📝 Filename copied to download form!', true);
                });

                // Keyboard support for filename
                row.querySelector('.file-name').addEventListener('keydown', (e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        e.target.click();
                    }
                });
                
                // Copy button
                row.querySelector('.copy-btn').addEventListener('click', async () => {
                    try {
                        await navigator.clipboard.writeText(file.name);
                        showToast('📋 Filename copied to clipboard!', true);
                    } catch {
                        showToast('❌ Could not copy to clipboard.', false);
                    }
                });
                
                // Delete button
                row.querySelector('.delete-btn').addEventListener('click', async (evt) => {
                    const filename = evt.target.dataset.filename;
                    if (confirm(`Are you sure you want to delete "${filename}"? This cannot be undone.`)) {
                        await deleteFile(filename);
                    }
                });
                
                tbody.appendChild(row);
            });
            
            listEl.style.display = 'block';
        } else {
            emptyEl.style.display = 'block';
        }
    } catch {
        loadingEl.style.display = 'none';
        showToast('❌ Could not load file list.', false);
    }
}

async function deleteFile(filename) {
    try {
        const response = await fetch(`/api/files/${encodeURIComponent(filename)}`, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': csrfToken
            }
        });
        const result = await response.json();
        showToast(result.message, result.success);
        
        if (result.success) {
            loadFiles(); // Refresh list
        }
    } catch {
        showToast('❌ Could not delete file.', false);
    }
}

// Refresh button
document.getElementById('refresh-files').addEventListener('click', loadFiles);

// ================== PASSWORD VALIDATION ==================
function validatePassword(password) {
    if (password.length < 8) {
        return { valid: false, message: '❌ Password must be at least 8 characters.' };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, message: '❌ Password must contain an uppercase letter.' };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, message: '❌ Password must contain a lowercase letter.' };
    }
    if (!/\d/.test(password)) {
        return { valid: false, message: '❌ Password must contain a number.' };
    }
    return { valid: true, message: '' };
}

// Password strength indicator
const passwordInput = document.getElementById('password');
const strengthIndicator = document.getElementById('password-strength');

passwordInput.addEventListener('input', function() {
    const password = this.value;
    updatePasswordStrength(password);
});

function updatePasswordStrength(password) {
    if (!password) {
        strengthIndicator.innerHTML = '';
        return;
    }
    
    let strength = 0;
    let feedback = [];
    
    if (password.length >= 8) strength++;
    else feedback.push('8+ chars');
    
    if (/[A-Z]/.test(password)) strength++;
    else feedback.push('uppercase');
    
    if (/[a-z]/.test(password)) strength++;
    else feedback.push('lowercase');
    
    if (/\d/.test(password)) strength++;
    else feedback.push('number');
    
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    const classes = ['very-weak', 'weak', 'fair', 'good', 'strong'];
    
    let html = `<div class="strength-bar ${classes[strength - 1] || classes[0]}">
        <div class="strength-fill" style="width: ${strength * 20}%"></div>
    </div>
    <small class="strength-text ${classes[strength - 1] || classes[0]}">${labels[strength - 1] || labels[0]}`;
    
    if (feedback.length > 0) {
        html += ` - Missing: ${feedback.join(', ')}`;
    }
    html += '</small>';
    
    strengthIndicator.innerHTML = html;
}

function resetPasswordStrength() {
    strengthIndicator.innerHTML = '';
}

// ================== PASSWORD VISIBILITY TOGGLE ==================
document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', function() {
        const targetId = this.dataset.target;
        const input = document.getElementById(targetId);
        
        if (input.type === 'password') {
            input.type = 'text';
            this.textContent = '🙈';
        } else {
            input.type = 'password';
            this.textContent = '👁️';
        }
    });
});

// ================== UI UTILITIES ==================
function showToast(message, success = true) {
    const container = document.getElementById('toast-container');
    container.innerHTML = '';
    
    const toast = document.createElement('div');
    toast.className = `custom-toast ${success ? 'success' : 'error'}`;
    toast.textContent = message;
    container.appendChild(toast);
    
    setTimeout(() => toast.remove(), 4000);
}

function setButtonLoading(btn, loading) {
    const text = btn.querySelector('.btn-text');
    const spinner = btn.querySelector('.spinner-border');
    
    if (loading) {
        btn.disabled = true;
        text?.classList.add('d-none');
        spinner?.classList.remove('d-none');
    } else {
        btn.disabled = false;
        text?.classList.remove('d-none');
        spinner?.classList.add('d-none');
    }
}

function triggerShake(element) {
    element.classList.remove('upload-error-shake');
    void element.offsetWidth; // Force reflow
    element.classList.add('upload-error-shake');
    setTimeout(() => element.classList.remove('upload-error-shake'), 500);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ================== INITIALIZATION ==================
document.addEventListener('DOMContentLoaded', loadFiles);

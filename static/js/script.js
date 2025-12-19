/**
 * Secure File Share - Frontend JavaScript
 * Handles file upload/download, file listing, drag & drop, theme toggle, and UI interactions
 */

// Get CSRF token from meta tag
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

// Store selected file for upload
let selectedFile = null;

// ================== THEME TOGGLE ==================
const themeToggle = document.getElementById('theme-toggle');
const themeIcon = themeToggle?.querySelector('.theme-icon');
const html = document.documentElement;

// Load saved theme
const savedTheme = localStorage.getItem('theme') || 'dark';
html.setAttribute('data-theme', savedTheme);
updateThemeIcon(savedTheme);

themeToggle?.addEventListener('click', () => {
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
});

function updateThemeIcon(theme) {
    if (themeIcon) {
        themeIcon.textContent = theme === 'dark' ? '🌙' : '☀️';
    }
}

// ================== DRAG & DROP ==================
const dropZone = document.getElementById('drop-zone');
const dropOverlay = document.getElementById('drop-overlay');
const fileInput = document.getElementById('file');
const selectedFileEl = document.getElementById('selected-file');
const selectedFileName = document.getElementById('selected-file-name');
const clearFileBtn = document.getElementById('clear-file');

// Prevent default drag behaviors on document
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    document.body.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

// Show overlay when dragging over document
document.body.addEventListener('dragenter', () => {
    dropOverlay?.classList.add('active');
});

dropOverlay?.addEventListener('dragleave', (e) => {
    // Only hide if leaving the overlay itself
    if (e.target === dropOverlay) {
        dropOverlay.classList.remove('active');
    }
});

dropOverlay?.addEventListener('drop', (e) => {
    dropOverlay.classList.remove('active');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileSelect(files[0]);
    }
});

// Drop zone click to open file picker
dropZone?.addEventListener('click', () => {
    fileInput?.click();
});

// Drop zone keyboard access
dropZone?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput?.click();
    }
});

// Drop zone drag events
dropZone?.addEventListener('dragover', () => {
    dropZone.classList.add('drag-over');
});

dropZone?.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
});

dropZone?.addEventListener('drop', (e) => {
    dropZone.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileSelect(files[0]);
    }
});

// File input change
fileInput?.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

// Clear file button
clearFileBtn?.addEventListener('click', () => {
    clearSelectedFile();
});

function handleFileSelect(file) {
    // Check file size (16MB max)
    const maxSize = 16 * 1024 * 1024;
    if (file.size > maxSize) {
        showToast('❌ File too large. Maximum size is 16MB.', false);
        return;
    }
    
    selectedFile = file;
    
    // Update UI
    if (selectedFileEl && selectedFileName) {
        selectedFileName.textContent = `${file.name} (${formatFileSize(file.size)})`;
        selectedFileEl.style.display = 'flex';
    }
    
    // Hide drop zone
    if (dropZone) {
        dropZone.style.display = 'none';
    }
}

function clearSelectedFile() {
    selectedFile = null;
    if (fileInput) fileInput.value = '';
    if (selectedFileEl) selectedFileEl.style.display = 'none';
    if (dropZone) dropZone.style.display = 'flex';
}

// ================== UPLOAD HANDLING ==================
document.getElementById('upload-form')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    if (!selectedFile) {
        showToast('❌ Please select a file first.', false);
        return;
    }
    
    const form = e.target;
    const formData = new FormData();
    formData.append('csrf_token', csrfToken);
    formData.append('file', selectedFile);
    formData.append('password', document.getElementById('password').value);
    
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
            
            if (result.success) {
                // Show success with share link option
                showToast(result.message, true);
                
                // Show share link if available
                if (result.share_url) {
                    setTimeout(() => {
                        const fullShareUrl = window.location.origin + result.share_url;
                        
                        // Auto-copy share link to clipboard
                        navigator.clipboard.writeText(fullShareUrl).then(() => {
                           showToast(`📋 Link copied! Ready to share: ${result.filename}`, true);
                        }).catch(() => {
                           showToast(`📋 Share link: ${result.filename}`, true);
                        });
                        
                    }, 1500);
                }
                
                form.reset();
                clearSelectedFile();
                resetPasswordStrength();
                loadFiles();
            } else {
                showToast(result.message, false);
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
    
    xhr.open('POST', '/api/upload');
    xhr.setRequestHeader('X-CSRFToken', csrfToken);
    xhr.send(formData);
});

// ================== DOWNLOAD HANDLING ==================
document.getElementById('download-form')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const form = e.target;
    const formData = new FormData(form);
    const downloadBtn = document.getElementById('download-btn');
    
    setButtonLoading(downloadBtn, true);
    showToast('🔄 Preparing your download...', true);
    
    try {
        const response = await fetch('/download', {
            method: 'POST',
            headers: { 'X-CSRFToken': csrfToken },
            body: formData
        });
        
        const contentType = response.headers.get('content-type');
        
        if (contentType && contentType.includes('application/json')) {
            const result = await response.json();
            showToast(result.message, result.success);
        } else {
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
    
    if (loadingEl) loadingEl.style.display = 'block';
    if (emptyEl) emptyEl.style.display = 'none';
    if (listEl) listEl.style.display = 'none';
    
    try {
        const response = await fetch('/api/files', {
            headers: { 'X-CSRFToken': csrfToken }
        });
        const result = await response.json();
        
        if (loadingEl) loadingEl.style.display = 'none';
        
        if (result.success && result.files.length > 0) {
            tbody.innerHTML = '';
            
            result.files.forEach(file => {
                const icon = getFileIcon(file.name);
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>
                        <span class="file-name" role="button" tabindex="0" title="Click to fill download form">
                            ${icon} ${escapeHtml(file.name)}
                        </span>
                        <button class="btn btn-sm btn-link copy-btn p-0 ms-1" title="Copy filename">📋</button>
                    </td>
                    <td>${formatFileSize(file.size)}</td>
                    <td><span class="badge bg-secondary">${file.downloads || 0}</span></td>
                    <td><span class="badge ${file.expires_in === 'Expired' ? 'bg-danger' : 'bg-warning text-dark'}">${file.expires_in || 'Unknown'}</span></td>
                    <td>
                        ${file.share_token ? `<button class="btn btn-sm btn-outline-info share-btn me-1" data-token="${escapeHtml(file.share_token)}" title="Copy share link">🔗</button>` : ''}
                        <button class="btn btn-sm btn-outline-danger delete-btn" data-filename="${escapeHtml(file.name)}" title="Delete file">🗑️</button>
                    </td>
                `;
                
                // Click filename to fill download form
                row.querySelector('.file-name')?.addEventListener('click', () => {
                    document.getElementById('filename').value = file.name;
                    document.getElementById('password_dl')?.focus();
                    showToast('📝 Filename copied to download form!', true);
                });
                
                // Copy filename button
                row.querySelector('.copy-btn')?.addEventListener('click', async () => {
                    try {
                        await navigator.clipboard.writeText(file.name);
                        showToast('📋 Filename copied to clipboard!', true);
                    } catch {
                        showToast('❌ Could not copy to clipboard.', false);
                    }
                });
                
                // Share link button
                row.querySelector('.share-btn')?.addEventListener('click', async (evt) => {
                    const token = evt.target.dataset.token;
                    const shareUrl = `${window.location.origin}/share/${token}`;
                    try {
                        await navigator.clipboard.writeText(shareUrl);
                        showToast('🔗 Share link copied to clipboard!', true);
                    } catch {
                        showToast('❌ Could not copy share link.', false);
                    }
                });
                
                // Delete button
                row.querySelector('.delete-btn')?.addEventListener('click', async (evt) => {
                    const filename = evt.target.dataset.filename;
                    if (confirm(`Delete "${filename}"? This cannot be undone.`)) {
                        await deleteFile(filename);
                    }
                });
                
                tbody.appendChild(row);
            });
            
            if (listEl) listEl.style.display = 'block';
        } else {
            if (emptyEl) emptyEl.style.display = 'block';
        }
    } catch {
        if (loadingEl) loadingEl.style.display = 'none';
        showToast('❌ Could not load file list.', false);
    }
}

async function deleteFile(filename) {
    // Prompt for password to confirm deletion
    const password = prompt(`Enter the encryption password to delete "${filename}":`);
    if (!password) return; // User cancelled
    
    try {
        const response = await fetch(`/api/files/${encodeURIComponent(filename)}`, {
            method: 'DELETE',
            headers: { 
                'X-CSRFToken': csrfToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: password })
        });
        const result = await response.json();
        showToast(result.message, result.success);
        
        if (result.success) {
            loadFiles();
        }
    } catch {
        showToast('❌ Could not delete file.', false);
    }
}

// Refresh button
document.getElementById('refresh-files')?.addEventListener('click', loadFiles);

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

passwordInput?.addEventListener('input', function() {
    updatePasswordStrength(this.value);
});

function updatePasswordStrength(password) {
    if (!strengthIndicator) return;
    
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
    if (strengthIndicator) strengthIndicator.innerHTML = '';
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
    if (!container) return;
    
    container.innerHTML = '';
    
    const toast = document.createElement('div');
    toast.className = `custom-toast ${success ? 'success' : 'error'}`;
    toast.textContent = message;
    container.appendChild(toast);
    
    setTimeout(() => toast.remove(), 4000);
}

function setButtonLoading(btn, loading) {
    if (!btn) return;
    
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
    if (!element) return;
    element.classList.remove('upload-error-shake');
    void element.offsetWidth;
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

function getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const icons = {
        'pdf': '📕',
        'doc': '📘', 'docx': '📘',
        'xls': '📗', 'xlsx': '📗', 'csv': '📊',
        'ppt': '📙', 'pptx': '📙',
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'svg': '🖼️',
        'zip': '📦', 'rar': '📦', '7z': '📦', 'tar': '📦', 'gz': '📦',
        'mp3': '🎵', 'wav': '🎵', 'ogg': '🎵',
        'mp4': '🎬', 'avi': '🎬', 'mkv': '🎬', 'mov': '🎬',
        'txt': '📝', 'md': '📝', 'json': '📝', 'xml': '📝',
        'py': '🐍', 'js': '📜', 'html': '🌐', 'css': '🎨'
    };
    return icons[ext] || '📄';
}

// Generate Password Button
document.getElementById('generate-password')?.addEventListener('click', () => {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    const length = 16;
    let passwordChars = [];

    // Helper for secure random integer
    const getSecureRandomInt = (max) => {
        const array = new Uint32Array(1);
        window.crypto.getRandomValues(array);
        return array[0] % max;
    };

    // Ensure at least one of each required type
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const numbers = "0123456789";

    passwordChars.push(upper[getSecureRandomInt(upper.length)]);
    passwordChars.push(lower[getSecureRandomInt(lower.length)]);
    passwordChars.push(numbers[getSecureRandomInt(numbers.length)]);

    // Fill the rest
    for (let i = 3; i < length; i++) {
        passwordChars.push(chars[getSecureRandomInt(chars.length)]);
    }

    // Fisher-Yates Shuffle
    for (let i = passwordChars.length - 1; i > 0; i--) {
        const j = getSecureRandomInt(i + 1);
        [passwordChars[i], passwordChars[j]] = [passwordChars[j], passwordChars[i]];
    }

    const password = passwordChars.join('');

    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.value = password;
        passwordInput.type = 'text'; // Show it so they can see/copy it

        // Update toggle icon
        const toggleBtn = document.querySelector('.toggle-password[data-target="password"]');
        if (toggleBtn) toggleBtn.textContent = '🙈';

        // Trigger input event to update strength meter
        passwordInput.dispatchEvent(new Event('input'));

        showToast('🎲 Secure password generated!', true);
    }
});

// ================== INITIALIZATION ==================
document.addEventListener('DOMContentLoaded', () => {
    // Only load files if we are on the main page (file table exists)
    if (document.getElementById('files-tbody')) {
        loadFiles();
    }

    // ================== QR CODE ==================
    let qrGenerated = false;
    document.getElementById('qr-btn')?.addEventListener('click', () => {
        if (qrGenerated) return;

        // Check if QRCode library is loaded
        if (typeof QRCode === 'undefined') {
            console.error('QRCode library not loaded');
            return;
        }

        const shareUrl = window.location.href;
        const qrContainer = document.getElementById("qrcode");
        if (qrContainer) {
            new QRCode(qrContainer, {
                text: shareUrl,
                width: 128,
                height: 128,
                colorDark : "#000000",
                colorLight : "#ffffff",
                correctLevel : QRCode.CorrectLevel.H
            });
            qrGenerated = true;
        }
    });
});

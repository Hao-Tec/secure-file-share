/**
 * Secure File Share - Frontend JavaScript
 * Handles file upload/download, file listing, drag & drop, theme toggle, and UI interactions
 */

// Get CSRF token from meta tag
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

// Store selected file for upload
let selectedFile = null;

// ================== SHARE TOKEN STORAGE (localStorage) ==================
// Stores share tokens locally so they persist across page loads
// This keeps tokens private (not exposed in public API)
const SHARE_TOKENS_KEY = 'cipherVaultShareTokens';

function saveShareToken(fileId, shareToken) {
    try {
        const tokens = JSON.parse(localStorage.getItem(SHARE_TOKENS_KEY) || '{}');
        tokens[fileId] = shareToken;
        localStorage.setItem(SHARE_TOKENS_KEY, JSON.stringify(tokens));
    } catch { /* localStorage not available */ }
}

function getShareToken(fileId) {
    try {
        const tokens = JSON.parse(localStorage.getItem(SHARE_TOKENS_KEY) || '{}');
        return tokens[fileId] || null;
    } catch { return null; }
}

function removeShareToken(fileId) {
    try {
        const tokens = JSON.parse(localStorage.getItem(SHARE_TOKENS_KEY) || '{}');
        delete tokens[fileId];
        localStorage.setItem(SHARE_TOKENS_KEY, JSON.stringify(tokens));
    } catch { /* localStorage not available */ }
}

// ================== CUSTOM TOOLTIP SYSTEM ==================
// Creates a premium, fast tooltip that replaces slow browser defaults
const tooltipEl = document.createElement('div');
tooltipEl.className = 'custom-tooltip';
document.body.appendChild(tooltipEl);

let tooltipTimeout = null;

function showCustomTooltip(element, text) {
    if (!text) return;
    
    clearTimeout(tooltipTimeout);
    
    const rect = element.getBoundingClientRect();
    const tooltipWidth = Math.min(400, text.length * 7 + 28);
    
    // Position below element, centered or aligned to left
    let left = rect.left + (rect.width / 2) - (tooltipWidth / 2);
    let top = rect.bottom + 8;
    
    // Keep tooltip within viewport
    if (left < 10) left = 10;
    if (left + tooltipWidth > window.innerWidth - 10) {
        left = window.innerWidth - tooltipWidth - 10;
    }
    
    // If below viewport, show above
    const showAbove = top + 80 > window.innerHeight;
    if (showAbove) {
        top = rect.top - 50;
        tooltipEl.classList.add('tooltip-top');
    } else {
        tooltipEl.classList.remove('tooltip-top');
    }
    
    tooltipEl.style.left = `${left}px`;
    tooltipEl.style.top = `${top}px`;
    tooltipEl.textContent = text;
    
    // Instant appearance (no delay like browser default)
    requestAnimationFrame(() => {
        tooltipEl.classList.add('visible');
    });
}

function hideCustomTooltip() {
    tooltipEl.classList.remove('visible');
    currentTooltipTarget = null;
}

// Track current tooltip target
let currentTooltipTarget = null;

// Helper to get tooltip text from element (data-tooltip or title)
function getTooltipText(element) {
    if (element.dataset.tooltip) return element.dataset.tooltip;
    if (element.title) {
        // Move title to data-tooltip to prevent browser default
        element.dataset.tooltip = element.title;
        element.removeAttribute('title');
        return element.dataset.tooltip;
    }
    return null;
}

// Event delegation for custom tooltips on elements with data-tooltip OR title
document.addEventListener('mouseenter', (e) => {
    const target = e.target.closest('[data-tooltip], [title]');
    if (target) {
        const text = getTooltipText(target);
        if (text) {
            currentTooltipTarget = target;
            showCustomTooltip(target, text);
        }
    }
}, true);

document.addEventListener('mouseleave', (e) => {
    const target = e.target.closest('[data-tooltip]');
    if (target) {
        hideCustomTooltip();
    }
}, true);

// Safety listeners - hide tooltip on scroll, blur, or Escape key
window.addEventListener('scroll', hideCustomTooltip, true);
window.addEventListener('blur', hideCustomTooltip);
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hideCustomTooltip();
});

// Fallback: hide if mouse moves significantly and not over tooltip target
document.addEventListener('mousemove', (e) => {
    if (!currentTooltipTarget) return;
    const rect = currentTooltipTarget.getBoundingClientRect();
    const buffer = 20;
    if (e.clientX < rect.left - buffer || e.clientX > rect.right + buffer ||
        e.clientY < rect.top - buffer || e.clientY > rect.bottom + buffer) {
        hideCustomTooltip();
    }
});

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
                
                // Store upload info for email package download
                const uploadedFileId = result.file_id;
                const uploadedPassword = document.getElementById('password')?.value;
                
                // Show share link if available
                if (result.share_url) {
                    // Save share token to localStorage for this file
                    // Extract token from URL: /share/{token}
                    const shareToken = result.share_url.split('/share/').pop();
                    saveShareToken(uploadedFileId, shareToken);
                    
                    setTimeout(() => {
                        // Show styled action toast with buttons
                        showUploadSuccessActions(result.share_url, result.filename, uploadedFileId, uploadedPassword);
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
document.getElementById('download-form')?.addEventListener('submit', async function(e) {e.preventDefault();
    
    const form = e.target;
    const downloadBtn = document.getElementById('download-btn');
    
    // Check if we're on share page or main page
    const isSharePage = window.location.pathname.startsWith('/share/');
    
    // Get password from appropriate input field
    const password = isSharePage 
        ? document.getElementById('password')?.value 
        : document.getElementById('password_dl')?.value;
    
    if (!password) {
        showToast('❌ Password is required.', false);
        return;
    }
    
    setButtonLoading(downloadBtn, true);
    showToast('🔄 Preparing your download...', true);
    
    try {
        let response;
        
        if (isSharePage) {
            // Share page: use token from URL
            const pathParts = window.location.pathname.split('/');
            const token = pathParts[pathParts.length - 1];
            
            if (!token) {
                showToast('❌ Invalid share link.', false);
                setButtonLoading(downloadBtn, false);
                return;
            }
            
            response = await fetch(`/api/download/${token}`, {
                method: 'POST',
                headers: { 
                    'X-CSRFToken': csrfToken,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: password })
            });
        } else {
            // Main page: use filename from form
            const filename = document.getElementById('filename')?.value;
            
            if (!filename) {
                showToast('❌ Filename is required.', false);
                setButtonLoading(downloadBtn, false);
                return;
            }
            
            // Find the share token for this filename from the files list
            const filesResponse = await fetch('/api/files', {
                headers: { 'X-CSRFToken': csrfToken }
            });
            const filesResult = await filesResponse.json();
            
            const file = filesResult.files?.find(f => f.name === filename);
            
            if (!file || !file.share_token) {
                showToast('❌ File not found.', false);
                setButtonLoading(downloadBtn, false);
                return;
            }
            
            response = await fetch(`/api/download/${file.share_token}`, {
                method: 'POST',
                headers: { 
                    'X-CSRFToken': csrfToken,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: password })
            });
        }
        
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
            
            const filename = form.filename?.value || 'downloaded_file';
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);
            form.reset();
        }
    } catch (error) {
        console.error('Download error:', error);
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
            
            // OPTIMIZATION: Use DocumentFragment to batch DOM updates and minimize reflows
            const fragment = document.createDocumentFragment();


            result.files.forEach(file => {
                const icon = getFileIcon(file.name);
                
                // Truncate long filenames (max 40 chars, preserve extension)
                const maxLen = 40;
                let displayName = file.name;
                if (file.name.length > maxLen) {
                    const ext = file.name.includes('.') ? file.name.split('.').pop() : '';
                    const nameWithoutExt = file.name.replace(`.${ext}`, '');
                    const truncatedName = nameWithoutExt.substring(0, maxLen - ext.length - 4);
                    displayName = `${truncatedName}...${ext ? '.' + ext : ''}`;
                }
                
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>
                        <div class="file-cell">
                            <span class="file-icon">${icon}</span>
                            <span class="file-name" role="button" tabindex="0" data-tooltip="${escapeAttr(file.name)}">${escapeHtml(displayName)}</span>
                            <button class="btn btn-sm btn-link copy-btn p-0" title="Copy filename" aria-label="Copy filename: ${escapeAttr(file.name)}">📋</button>
                        </div>
                    </td>
                    <td>${formatFileSize(file.size)}</td>
                    <td><span class="badge bg-secondary">${file.downloads || 0}</span></td>
                    <td><span class="badge ${file.expires_in === 'Expired' ? 'bg-danger' : 'bg-warning text-dark'}">${file.expires_in || 'Unknown'}</span></td>
                    <td>
                        <div class="action-btns">
                            ${getShareToken(file.file_id) ? `<button class="btn btn-sm btn-outline-info share-btn" data-token="${escapeAttr(getShareToken(file.file_id))}" title="Copy share link" aria-label="Copy share link for ${escapeAttr(file.name)}">🔗</button>` : '<span class="action-placeholder"></span>'}
                            <button class="btn btn-sm btn-outline-primary email-pkg-btn" data-fileid="${escapeAttr(file.file_id)}" data-displayname="${escapeAttr(file.name)}" title="Download for Email" aria-label="Download email package for ${escapeAttr(file.name)}">📧</button>
                            <button class="btn btn-sm btn-outline-danger delete-btn" data-fileid="${escapeAttr(file.file_id)}" data-displayname="${escapeAttr(file.name)}" title="Delete file" aria-label="Delete ${escapeAttr(file.name)}">🗑️</button>
                        </div>
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
                
                // Share link button (uses localStorage cached token)
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
                    const fileId = evt.target.dataset.fileid;
                    const displayName = evt.target.dataset.displayname;
                    // Show custom modal (removed browser confirm)
                    await deleteFile(fileId, displayName);
                });

                // Email Package button
                row.querySelector('.email-pkg-btn')?.addEventListener('click', async (evt) => {
                    const fileId = evt.target.dataset.fileid;
                    const displayName = evt.target.dataset.displayname;
                    await downloadEmailPackage(fileId, displayName);
                });
                
                fragment.appendChild(row);
            });
            
            tbody.appendChild(fragment);

            if (listEl) listEl.style.display = 'block';
        } else {
            if (emptyEl) emptyEl.style.display = 'block';
        }
    } catch {
        if (loadingEl) loadingEl.style.display = 'none';
        showToast('❌ Could not load file list.', false);
    }
}

// ================== DELETE MODAL HANDLING ==================
let currentDeleteFileId = null;
let currentDeleteFileName = null;

const deleteModal = document.getElementById('delete-modal');
const deleteFilenameEl = document.getElementById('delete-filename');
const deletePasswordInput = document.getElementById('delete-password');
const deleteCancelBtn = document.getElementById('delete-cancel-btn');
const deleteConfirmBtn = document.getElementById('delete-confirm-btn');
const deleteModalClose = document.querySelector('.delete-modal-close');

// Function to show delete modal
function showDeleteModal(fileId, fileName) {
    currentDeleteFileId = fileId;
    currentDeleteFileName = fileName;
    
    deleteFilenameEl.textContent = fileName;
    deletePasswordInput.value = '';
    deleteModal.classList.add('active');
    
    // Focus password input
    setTimeout(() => deletePasswordInput.focus(), 100);
    
    // Prevent body scroll
    document.body.style.overflow = 'hidden';
}

// Function to close delete modal
function closeDeleteModal() {
    deleteModal.classList.remove('active');
    deletePasswordInput.value = '';
    currentDeleteFileId = null;
    currentDeleteFileName = null;
    
    // Restore body scroll
    document.body.style.overflow = '';
}

// Close modal on backdrop click
deleteModal?.querySelector('.delete-modal-backdrop')?.addEventListener('click', closeDeleteModal);

// Close modal on X button
deleteModalClose?.addEventListener('click', closeDeleteModal);

// Close modal on Cancel button
deleteCancelBtn?.addEventListener('click', closeDeleteModal);

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && deleteModal?.classList.contains('active')) {
        closeDeleteModal();
    }
});

// Submit on Enter key in password input
deletePasswordInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        deleteConfirmBtn?.click();
    }
});

// Confirm deletion
deleteConfirmBtn?.addEventListener('click', async () => {
    const password = deletePasswordInput?.value;
    
    if (!password) {
        showToast('❌ Password is required.', false);
        deletePasswordInput?.focus();
        return;
    }
    
    // Show loading
    setButtonLoading(deleteConfirmBtn, true);
    
    try {
        const response = await fetch(`/api/files/${encodeURIComponent(currentDeleteFileId)}`, {
            method: 'DELETE',
            headers: { 
                'X-CSRFToken': csrfToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: password })
        });
        const result = await response.json();
        
        setButtonLoading(deleteConfirmBtn, false);
        
        showToast(result.message, result.success);
        
        if (result.success) {
            closeDeleteModal();
            loadFiles();
        }
    } catch {
        setButtonLoading(deleteConfirmBtn, false);
        showToast('❌ Could not delete file.', false);
    }
});

async function deleteFile(fileId, displayName = 'this file') {
    // Show custom modal instead of browser prompt
    showDeleteModal(fileId, displayName);
}

// ================== EMAIL PACKAGE MODAL HANDLING ==================
let currentEmailPackageFileId = null;
let currentEmailPackageFileName = null;

const emailPkgModal = document.getElementById('email-pkg-modal');
const emailPkgFilenameEl = document.getElementById('email-pkg-filename');
const emailPkgPasswordInput = document.getElementById('email-pkg-password');
const emailPkgCancelBtn = document.getElementById('email-pkg-cancel-btn');
const emailPkgConfirmBtn = document.getElementById('email-pkg-confirm-btn');
const emailPkgModalClose = document.querySelector('.email-pkg-close');

/**
 * Helper function to fetch and download email package
 * Used by modal confirm, quick download toast, and upload success actions
 * @param {string} fileId - The file ID to download
 * @param {string} password - The password for decryption
 * @param {string} downloadFilename - Suggested filename for download
 * @returns {Promise<{success: boolean, message?: string}>}
 */
async function fetchAndDownloadEmailPackage(fileId, password, downloadFilename) {
    try {
        const response = await fetch(`/api/download-package/${encodeURIComponent(fileId)}`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: password })
        });
        
        const contentType = response.headers.get('content-type');
        
        if (contentType && contentType.includes('text/html')) {
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = response.headers.get('content-disposition')?.split('filename=')[1]?.replace(/"/g, '') || downloadFilename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            loadFiles(); // Refresh to show updated download count
            return { success: true };
        } else {
            const result = await response.json();
            return { success: false, message: result.message || '❌ Could not generate package.' };
        }
    } catch (error) {
        console.error('Email package fetch error:', error);
        return { success: false, message: '❌ Network error. Please try again.' };
    }
}

// Function to show email package modal
function showEmailPkgModal(fileId, fileName) {
    currentEmailPackageFileId = fileId;
    currentEmailPackageFileName = fileName;
    
    if (emailPkgFilenameEl) emailPkgFilenameEl.textContent = fileName;
    if (emailPkgPasswordInput) emailPkgPasswordInput.value = '';
    emailPkgModal?.classList.add('active');
    
    // Focus password input
    setTimeout(() => emailPkgPasswordInput?.focus(), 100);
    
    // Prevent body scroll
    document.body.style.overflow = 'hidden';
}

// Function to close email package modal
function closeEmailPkgModal() {
    emailPkgModal?.classList.remove('active');
    if (emailPkgPasswordInput) emailPkgPasswordInput.value = '';
    currentEmailPackageFileId = null;
    currentEmailPackageFileName = null;
    
    // Restore body scroll
    document.body.style.overflow = '';
}

// Close modal on backdrop click
emailPkgModal?.querySelector('.delete-modal-backdrop')?.addEventListener('click', closeEmailPkgModal);

// Close modal on X button
emailPkgModalClose?.addEventListener('click', closeEmailPkgModal);

// Close modal on Cancel button
emailPkgCancelBtn?.addEventListener('click', closeEmailPkgModal);

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && emailPkgModal?.classList.contains('active')) {
        closeEmailPkgModal();
    }
});

// Confirm generation
emailPkgConfirmBtn?.addEventListener('click', async () => {
    const password = emailPkgPasswordInput?.value;
    
    if (!password) {
        showToast('❌ Password is required.', false);
        emailPkgPasswordInput?.focus();
        return;
    }
    
    // Show loading
    setButtonLoading(emailPkgConfirmBtn, true);
    
    const result = await fetchAndDownloadEmailPackage(
        currentEmailPackageFileId, 
        password, 
        `${currentEmailPackageFileName}_encrypted.html`
    );
    
    setButtonLoading(emailPkgConfirmBtn, false);
    
    if (result.success) {
        closeEmailPkgModal();
        showToast('✅ Email package downloaded! Attach it to your email.', true);
    } else {
        showToast(result.message, false);
    }
});

// Enter key to submit
emailPkgPasswordInput?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        emailPkgConfirmBtn?.click();
    }
});

// Main function called from file list
async function downloadEmailPackage(fileId, displayName) {
    showEmailPkgModal(fileId, displayName);
}

// Show email download option after successful upload (auto-downloads with stored password)
// Show upload success actions with styled buttons (no auto-copy = no permission popup)
function showUploadSuccessActions(shareUrl, filename, fileId, password) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    // Truncate filename if too long (keep extension visible)
    const maxLen = 35;
    let displayName = filename;
    if (filename.length > maxLen) {
        const ext = filename.includes('.') ? filename.split('.').pop() : '';
        const nameWithoutExt = filename.replace(`.${ext}`, '');
        const truncatedName = nameWithoutExt.substring(0, maxLen - ext.length - 4);
        displayName = `${truncatedName}...${ext ? '.' + ext : ''}`;
    }
    
    const toast = document.createElement('div');
    toast.className = 'custom-toast success';
    toast.style.animation = 'slideIn 0.4s ease';
    toast.style.maxWidth = '400px';
    toast.innerHTML = `
        <div style="margin-bottom: 10px;">
            <strong title="${filename}">🎉 ${displayName}</strong>
        </div>
        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
            <button class="btn btn-sm btn-primary copy-link-btn" style="padding: 6px 14px; font-size: 0.85rem;">
                📋 Copy Share Link
            </button>
            ${fileId && password ? `
            <button class="btn btn-sm btn-outline-primary email-pkg-btn-quick" style="padding: 6px 14px; font-size: 0.85rem;">
                📧 Email Package
            </button>
            ` : ''}
        </div>
    `;
    
    container.appendChild(toast);
    
    // Copy link button
    toast.querySelector('.copy-link-btn')?.addEventListener('click', async () => {
        const btn = toast.querySelector('.copy-link-btn');
        try {
            await navigator.clipboard.writeText(shareUrl);
            btn.textContent = '✓ Copied!';
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-success');
            setTimeout(() => {
                btn.textContent = '📋 Copy Share Link';
                btn.classList.remove('btn-success');
                btn.classList.add('btn-primary');
            }, 2000);
        } catch {
            // Fallback: show link in prompt
            prompt('Copy this share link:', shareUrl);
        }
    });
    
    // Email package button
    toast.querySelector('.email-pkg-btn-quick')?.addEventListener('click', async () => {
        const btn = toast.querySelector('.email-pkg-btn-quick');
        btn.textContent = '⏳ Generating...';
        btn.disabled = true;
        
        try {
            const response = await fetch(`/api/download-package/${encodeURIComponent(fileId)}`, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': csrfToken,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: password })
            });
            
            const contentType = response.headers.get('content-type');
            
            if (contentType && contentType.includes('text/html')) {
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${filename.split('.')[0]}_encrypted.html`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                btn.textContent = '✓ Downloaded!';
                btn.classList.remove('btn-outline-primary');
                btn.classList.add('btn-success');
                loadFiles();
            } else {
                const result = await response.json();
                btn.textContent = result.message || '❌ Failed';
            }
        } catch (error) {
            console.error('Email package error:', error);
            btn.textContent = '❌ Failed';
        }
    });
    
    // Auto-remove after 30 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.style.animation = 'fadeOut 0.4s ease forwards';
            setTimeout(() => toast.remove(), 400);
        }
    }, 30000);
}

async function showEmailDownloadOption(fileId, filename, password) {
    // Create a special toast with a download button
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = 'custom-toast success';
    toast.style.animation = 'slideIn 0.4s ease';
    toast.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
            <span>📧 Want to share via email?</span>
            <button class="btn btn-sm btn-primary email-quick-download" style="padding: 4px 12px; font-size: 0.8rem;">
                Download Package
            </button>
        </div>
    `;
    
    container.appendChild(toast);
    
    // Handle click
    toast.querySelector('.email-quick-download')?.addEventListener('click', async () => {
        toast.querySelector('.email-quick-download').textContent = '⏳ Generating...';
        toast.querySelector('.email-quick-download').disabled = true;
        
        try {
            const response = await fetch(`/api/download-package/${encodeURIComponent(fileId)}`, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': csrfToken,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: password })
            });
            
            const contentType = response.headers.get('content-type');
            
            if (contentType && contentType.includes('text/html')) {
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${filename.split('.')[0]}_encrypted.html`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                
                toast.innerHTML = '<span>✅ Email package downloaded!</span>';
                setTimeout(() => toast.remove(), 3000);
                loadFiles(); // Refresh to show updated download count
            } else {
                const result = await response.json();
                toast.innerHTML = `<span>${result.message || '❌ Failed'}</span>`;
                setTimeout(() => toast.remove(), 3000);
            }
        } catch (error) {
            console.error('Quick download error:', error);
            toast.innerHTML = '<span>❌ Download failed</span>';
            setTimeout(() => toast.remove(), 3000);
        }
    });
    
    // Auto-remove after 15 seconds if not clicked
    setTimeout(() => {
        if (toast.parentNode) {
            toast.style.animation = 'fadeOut 0.4s ease forwards';
            setTimeout(() => toast.remove(), 400);
        }
    }, 15000);
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

function escapeAttr(text) {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
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

        // Auto-copy to clipboard
        navigator.clipboard.writeText(password).then(() => {
            showToast('🎲 Secure password generated and copied to clipboard!', true);
        }).catch(() => {
            showToast('🎲 Secure password generated!', true);
        });
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

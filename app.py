"""Secure File Share - Flask Application with AES Encryption."""
import os
import re
import uuid
import json
import time
from datetime import datetime, timedelta
from flask import Flask, request, render_template, send_file, jsonify, abort
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename
from io import BytesIO

from config import get_config

# Initialize Flask app
app = Flask(__name__)
config = get_config()

# Apply configuration
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['WTF_CSRF_ENABLED'] = config.WTF_CSRF_ENABLED
app.config['WTF_CSRF_TIME_LIMIT'] = config.WTF_CSRF_TIME_LIMIT

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter with strict enforcement
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per hour"],
    storage_uri="memory://",
    headers_enabled=True,  # Add rate limit headers to responses
    swallow_errors=False   # Don't swallow errors, enforce limits strictly
)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Constants
SALT_LENGTH = 16
NONCE_LENGTH = 16
TAG_LENGTH = 16
FILE_EXPIRY_DAYS = 7  # Files expire after 7 days


# ==================== METADATA HELPERS ====================

def get_metadata_path(enc_path: str) -> str:
    """Get the metadata file path for an encrypted file."""
    return enc_path + ".meta"


def create_metadata(enc_path: str, original_filename: str) -> dict:
    """Create metadata for a newly uploaded file."""
    share_token = uuid.uuid4().hex[:12]  # 12 char share token
    now = datetime.utcnow()
    expires = now + timedelta(days=FILE_EXPIRY_DAYS)
    
    metadata = {
        "original_name": original_filename,
        "uploaded_at": now.isoformat() + "Z",
        "expires_at": expires.isoformat() + "Z",
        "downloads": 0,
        "share_token": share_token
    }
    
    meta_path = get_metadata_path(enc_path)
    with open(meta_path, "w") as f:
        json.dump(metadata, f)
    
    return metadata


def load_metadata(enc_path: str) -> dict | None:
    """Load metadata for a file, or return None if not found."""
    meta_path = get_metadata_path(enc_path)
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    return None


def update_metadata(enc_path: str, updates: dict) -> bool:
    """Update specific fields in metadata."""
    metadata = load_metadata(enc_path)
    if metadata:
        metadata.update(updates)
        meta_path = get_metadata_path(enc_path)
        with open(meta_path, "w") as f:
            json.dump(metadata, f)
        return True
    return False


def increment_download_count(enc_path: str) -> int:
    """Increment and return the download count."""
    metadata = load_metadata(enc_path)
    if metadata:
        new_count = metadata.get("downloads", 0) + 1
        update_metadata(enc_path, {"downloads": new_count})
        return new_count
    return 0


def is_file_expired(metadata: dict) -> bool:
    """Check if a file has expired."""
    if not metadata or "expires_at" not in metadata:
        return False
    try:
        expires = datetime.fromisoformat(metadata["expires_at"].replace("Z", ""))
        return datetime.utcnow() > expires
    except (ValueError, TypeError):
        return False


def get_time_remaining(metadata: dict) -> str:
    """Get human-readable time remaining until expiry."""
    if not metadata or "expires_at" not in metadata:
        return "Unknown"
    try:
        expires = datetime.fromisoformat(metadata["expires_at"].replace("Z", ""))
        remaining = expires - datetime.utcnow()
        
        if remaining.total_seconds() <= 0:
            return "Expired"
        
        days = remaining.days
        hours = remaining.seconds // 3600
        
        if days > 0:
            return f"{days}d {hours}h"
        elif hours > 0:
            return f"{hours}h"
        else:
            minutes = remaining.seconds // 60
            return f"{minutes}m"
    except (ValueError, TypeError):
        return "Unknown"


def find_file_by_share_token(token: str) -> tuple[str, dict] | tuple[None, None]:
    """Find a file by its share token. Returns (enc_path, metadata) or (None, None)."""
    upload_folder = app.config['UPLOAD_FOLDER']
    try:
        with os.scandir(upload_folder) as entries:
            for entry in entries:
                if entry.name.endswith(".enc") and entry.is_file():
                    enc_path = entry.path
                    metadata = load_metadata(enc_path)
                    if metadata and metadata.get("share_token") == token:
                        return enc_path, metadata
    except Exception:
        pass
    return None, None


# ==================== VALIDATION HELPERS ====================

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password meets security requirements."""
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    
    return True, ""


def allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed."""
    if '.' not in filename:
        return True
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in config.ALLOWED_EXTENSIONS


# ==================== ENCRYPTION HELPERS ====================

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 128-bit key from password and salt using PBKDF2."""
    return PBKDF2(password, salt, dkLen=16, count=100000)


def encrypt_file(file_data: bytes, password: str) -> bytes:
    """Encrypt file data using AES-EAX mode with a unique salt."""
    salt = get_random_bytes(SALT_LENGTH)
    key = derive_key(password, salt)
    
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    
    return salt + cipher.nonce + tag + ciphertext


def decrypt_file(file_data: bytes, password: str) -> bytes:
    """Decrypt file data that was encrypted with encrypt_file()."""
    salt = file_data[:SALT_LENGTH]
    nonce = file_data[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
    tag = file_data[SALT_LENGTH + NONCE_LENGTH:SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH]
    ciphertext = file_data[SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH:]
    
    key = derive_key(password, salt)
    
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ==================== ROUTES ====================

@app.route("/")
def index():
    """Render the main page."""
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
@limiter.limit("5 per hour", error_message="Too many uploads. Please wait before uploading more files.")
@limiter.limit("2 per minute", error_message="Please wait a moment before uploading another file.")
def upload():
    """Handle file upload with encryption."""
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "❌ No file provided."}), 400
    
    file = request.files["file"]
    password = request.form.get("password", "")
    
    if not file or file.filename == '':
        return jsonify({"success": False, "message": "❌ No file selected."}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"success": False, "message": "❌ File type not allowed."}), 400
    
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return jsonify({"success": False, "message": f"❌ {error_msg}"}), 400
    
    try:
        original_filename = secure_filename(file.filename)
        if not original_filename:
            return jsonify({"success": False, "message": "❌ Invalid filename."}), 400
        
        # Generate unique filename
        name, ext = os.path.splitext(original_filename)
        unique_id = uuid.uuid4().hex[:8]
        unique_filename = f"{name}_{unique_id}{ext}"
        
        file_data = file.read()
        encrypted_data = encrypt_file(file_data, password)
        
        enc_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename + ".enc")
        with open(enc_path, "wb") as f:
            f.write(encrypted_data)
        
        # Create metadata with share token and expiry
        metadata = create_metadata(enc_path, original_filename)
        share_url = f"/share/{metadata['share_token']}"
        
        return jsonify({
            "success": True,
            "message": f"✅ File uploaded! Expires in {FILE_EXPIRY_DAYS} days.",
            "filename": unique_filename,
            "share_token": metadata["share_token"],
            "share_url": share_url
        })
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return jsonify({"success": False, "message": "❌ An error occurred during upload."}), 500


@app.route("/download", methods=["POST"])
@limiter.limit("20 per hour", error_message="Too many downloads. Please wait.")
@limiter.limit("5 per minute", error_message="Please wait a moment before downloading again.")
def download():
    """Handle file download with decryption."""
    filename = request.form.get("filename", "")
    password = request.form.get("password", "")
    
    if not filename or not password:
        return jsonify({"success": False, "message": "❌ Filename and password are required."}), 400
    
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return jsonify({"success": False, "message": "❌ Invalid filename."}), 400
    
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename + ".enc")
    
    if not os.path.exists(enc_path):
        return jsonify({"success": False, "message": "❌ Encrypted file not found."}), 404
    
    # Check expiration
    metadata = load_metadata(enc_path)
    if metadata and is_file_expired(metadata):
        # Delete expired file
        try:
            os.remove(enc_path)
            meta_path = get_metadata_path(enc_path)
            if os.path.exists(meta_path):
                os.remove(meta_path)
        except Exception:
            pass
        return jsonify({"success": False, "message": "❌ This file has expired and been deleted."}), 410
    
    try:
        with open(enc_path, "rb") as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data, password)
        
        # Increment download counter
        increment_download_count(enc_path)
        
        return send_file(
            BytesIO(decrypted_data),
            download_name=safe_filename,
            as_attachment=True
        )
    except ValueError:
        return jsonify({"success": False, "message": "❌ Decryption failed. Check your password."}), 400
    except Exception as e:
        app.logger.error(f"Download error: {e}")
        return jsonify({"success": False, "message": "❌ An error occurred during download."}), 500


@app.route("/share/<token>")
def share_page(token):
    """Render a share page for a specific file."""
    enc_path, metadata = find_file_by_share_token(token)
    
    if not enc_path or not metadata:
        abort(404)
    
    if is_file_expired(metadata):
        # Clean up expired file
        try:
            os.remove(enc_path)
            meta_path = get_metadata_path(enc_path)
            if os.path.exists(meta_path):
                os.remove(meta_path)
        except Exception:
            pass
        abort(410)  # Gone
    
    # Get display filename from path
    filename = os.path.basename(enc_path)[:-4]  # Remove .enc
    time_remaining = get_time_remaining(metadata)
    
    return render_template("share.html", 
                         filename=filename, 
                         time_remaining=time_remaining,
                         downloads=metadata.get("downloads", 0))


@app.route("/api/files", methods=["GET"])
def list_files():
    """List all encrypted files with metadata."""
    try:
        files = []
        upload_folder = app.config['UPLOAD_FOLDER']
        now = datetime.utcnow()
        
        with os.scandir(upload_folder) as entries:
            for entry in entries:
                if entry.name.endswith(".enc") and entry.is_file():
                    enc_path = entry.path
                    stat = entry.stat()
                    metadata = load_metadata(enc_path)
                    
                    # Skip and delete expired files
                    if metadata and is_file_expired(metadata):
                        try:
                            os.remove(enc_path)
                            meta_path = get_metadata_path(enc_path)
                            if os.path.exists(meta_path):
                                os.remove(meta_path)
                        except Exception:
                            pass
                        continue
                    
                    display_name = entry.name[:-4]
                    
                    file_info = {
                        "name": display_name,
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                        "downloads": metadata.get("downloads", 0) if metadata else 0,
                        "expires_in": get_time_remaining(metadata) if metadata else "Unknown",
                        "share_token": metadata.get("share_token") if metadata else None
                    }
                    files.append(file_info)
        
        files.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({"success": True, "files": files})
    except Exception as e:
        app.logger.error(f"List files error: {e}")
        return jsonify({"success": False, "message": "❌ Could not retrieve file list."}), 500


@app.route("/api/files/<filename>", methods=["DELETE"])
@limiter.limit("10 per hour", error_message="Too many delete attempts. Please wait.")
def delete_file(filename):
    """Delete an encrypted file and its metadata. Requires password."""
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return jsonify({"success": False, "message": "❌ Invalid filename."}), 400
    
    # Get password from request
    password = None
    if request.is_json:
        password = request.json.get("password")

    if not password:
        return jsonify({"success": False, "message": "❌ Password is required to delete."}), 401

    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename + ".enc")
    meta_path = get_metadata_path(enc_path)
    
    if not os.path.exists(enc_path):
        return jsonify({"success": False, "message": "❌ File not found."}), 404
    
    # Verify password by attempting to decrypt
    try:
        with open(enc_path, "rb") as f:
            encrypted_data = f.read()

        # This will raise ValueError if password/tag is wrong
        decrypt_file(encrypted_data, password)

    except ValueError:
        return jsonify({"success": False, "message": "❌ Incorrect password."}), 403
    except Exception as e:
        app.logger.error(f"Delete verification error: {e}")
        return jsonify({"success": False, "message": "❌ Verification failed."}), 500

    try:
        os.remove(enc_path)
        if os.path.exists(meta_path):
            os.remove(meta_path)
        return jsonify({"success": True, "message": "✅ File deleted successfully."})
    except Exception as e:
        app.logger.error(f"Delete error: {e}")
        return jsonify({"success": False, "message": "❌ Could not delete file."}), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    max_size_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
    return jsonify({"success": False, "message": f"❌ File too large. Maximum size is {max_size_mb}MB."}), 413


@app.errorhandler(429)
def rate_limit_exceeded(error):
    """Handle rate limit exceeded error."""
    return jsonify({"success": False, "message": "❌ Too many requests. Please slow down."}), 429


@app.errorhandler(410)
def gone(error):
    """Handle expired resource error."""
    return render_template("expired.html"), 410


if __name__ == "__main__":
    app.run(debug=config.DEBUG, host='127.0.0.1', port=5000)

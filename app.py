"""Cipher Vault - Secure File Sharing with AES-256 Encryption."""

import os
import re
import uuid
from datetime import datetime, timedelta
from io import BytesIO
from typing import Tuple

from flask import Flask, request, render_template, send_file, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from werkzeug.utils import secure_filename

import database
from config import get_config

# Initialize Flask app
app = Flask(__name__)
config = get_config()

# Apply configuration
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["UPLOAD_FOLDER"] = (
    config.UPLOAD_FOLDER
)  # This is now mostly vestigial, but kept for config consistency
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
app.config["WTF_CSRF_ENABLED"] = config.WTF_CSRF_ENABLED
app.config["WTF_CSRF_TIME_LIMIT"] = config.WTF_CSRF_TIME_LIMIT

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter with strict enforcement
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per hour"],
    storage_uri="memory://",
    headers_enabled=True,  # Add rate limit headers to responses
    swallow_errors=False,  # Don't swallow errors, enforce limits strictly
)

# Crypto Constants
SALT_LENGTH = 16
NONCE_LENGTH = 16
TAG_LENGTH = 16
HEADER_LENGTH = SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH
FILE_EXPIRY_DAYS = 7  # Files expire after 7 days

# Precompiled password validation patterns (faster than compiling each call)
_PASSWORD_PATTERNS = {
    "uppercase": re.compile(r"[A-Z]"),
    "lowercase": re.compile(r"[a-z]"),
    "digit": re.compile(r"\d"),
    "special": re.compile(r'[!@#$%^&*(),.?":{}|<>]'),
}

# Initialize Database (will skip if no connection string)
try:
    with app.app_context():
        # Only init if we are in production or have DB_URL
        if os.environ.get("DATABASE_URL"):
            database.init_db()
except Exception as e:
    app.logger.warning("Database Init Warning: %s", e)


# Global variable for cleanup throttling
_last_cleanup_time = datetime.min
_cleanup_lock = False


# ==================== METADATA HELPERS ====================

# NOTE: With PostgreSQL, we use the database as the source of truth.
# The in-memory caching is less critical for small counts but we can
# keep a simple cache if needed. For now, let's rely on fast DB queries.


def create_metadata(original_filename: str) -> dict:
    """Create metadata for a newly uploaded file."""
    share_token = uuid.uuid4().hex[:12]  # 12 char share token
    now = datetime.utcnow()
    expires = now + timedelta(days=FILE_EXPIRY_DAYS)

    metadata = {
        "original_name": original_filename,
        "uploaded_at": now.isoformat() + "Z",
        "expires_at": expires.isoformat() + "Z",
        "downloads": 0,
        "share_token": share_token,
    }
    return metadata


def load_metadata(enc_path_or_filename: str) -> dict | None:
    """Load metadata from database (wrapper for consistency)."""
    # Filename is usually the basename (e.g. "uuid.enc")
    filename = os.path.basename(enc_path_or_filename)
    return database.get_metadata(filename)


def update_metadata(filename: str, updates: dict) -> bool:
    """Update specific fields in metadata."""
    filename = os.path.basename(filename)
    return database.update_metadata(filename, updates)


def increment_download_count(filename: str) -> int:
    """Increment and return the download count."""
    filename = os.path.basename(filename)
    # We use a database update
    metadata = database.get_metadata(filename)
    if metadata:
        new_count = metadata.get("downloads", 0) + 1
        database.update_metadata(filename, {"downloads": new_count})
        return new_count
    return 0


def find_file_by_share_token(token: str) -> tuple[str, dict] | tuple[None, None]:
    """Find a file by its share token via Database."""
    filename, metadata = database.find_by_token(token)
    if filename and metadata:
        return filename, metadata
    return None, None


# ==================== VALIDATION HELPERS ====================


def validate_password(password: str) -> Tuple[bool, str]:
    """Validate password meets security requirements using precompiled patterns."""
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return (
            False,
            f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters.",
        )

    if not _PASSWORD_PATTERNS["uppercase"].search(password):
        return False, "Password must contain at least one uppercase letter."

    if not _PASSWORD_PATTERNS["lowercase"].search(password):
        return False, "Password must contain at least one lowercase letter."

    if not _PASSWORD_PATTERNS["digit"].search(password):
        return False, "Password must contain at least one number."

    if not _PASSWORD_PATTERNS["special"].search(password):
        return False, "Password must contain at least one special character."

    return True, ""


def allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed."""
    if "." not in filename:
        return True
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in config.ALLOWED_EXTENSIONS


def is_file_expired(metadata: dict) -> bool:
    """Check if file is expired."""
    if not metadata or "expires_at" not in metadata:
        return False
    try:
        expires_at = datetime.fromisoformat(metadata["expires_at"].rstrip("Z"))
        return datetime.utcnow() > expires_at
    except (KeyError, ValueError):
        return True


def get_time_remaining(metadata: dict) -> str:
    """Get human readable time remaining string."""
    if not metadata or "expires_at" not in metadata:
        return "Unknown"
    try:
        expires_at = datetime.fromisoformat(metadata["expires_at"].rstrip("Z"))
        remaining = expires_at - datetime.utcnow()
        if remaining.total_seconds() <= 0:
            return "Expired"

        if remaining.days > 0:
            return f"{remaining.days}d {remaining.seconds // 3600}h"
        if remaining.seconds >= 3600:
            return f"{remaining.seconds // 3600}h"
        minutes = remaining.seconds // 60
        return f"{minutes}m"
    except (ValueError, TypeError):
        return "Unknown"


# ==================== CRYPTO HELPERS ====================
# (Keep helpers but update usage)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password and salt using PBKDF2."""
    return PBKDF2(password, salt, dkLen=32, count=100000)


def encrypt_file(file_data: bytes, password: str) -> bytes:
    """Encrypt file data with AES-256-EAX."""
    salt = get_random_bytes(SALT_LENGTH)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    # Combine salt + nonce + tag + ciphertext
    return salt + cipher.nonce + tag + ciphertext


def decrypt_file(file_data: bytes, password: str) -> bytes:
    """Decrypt file data that was encrypted with encrypt_file()."""
    # Extract components using precomputed offsets
    salt = file_data[:SALT_LENGTH]
    nonce_end = SALT_LENGTH + NONCE_LENGTH
    tag_end = nonce_end + TAG_LENGTH

    nonce = file_data[SALT_LENGTH:nonce_end]
    tag = file_data[nonce_end:tag_end]
    ciphertext = file_data[tag_end:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ==================== ROUTES ====================


@app.route("/")
def index():
    """Render the main page."""
    return render_template("index.html")


@app.route("/api/upload", methods=["POST"])
@limiter.limit(
    "5 per hour",
    error_message="Too many uploads. Please wait before uploading more files.",
)
@limiter.limit(
    "2 per minute", error_message="Please wait a moment before uploading another file."
)
def upload_file():
    """Handle file upload with encryption."""
    if "file" not in request.files:
        return jsonify({"success": False, "message": "❌ No file provided."}), 400

    file = request.files["file"]
    password = request.form.get("password", "")

    if not file or file.filename == "":
        return jsonify({"success": False, "message": "❌ No file selected."}), 400

    if not allowed_file(file.filename):
        ext = (
            file.filename.rsplit(".", 1)[-1].lower()
            if "." in file.filename
            else "unknown"
        )
        return (
            jsonify(
                {
                    "success": False,
                    "message": f"❌ .{ext} files not allowed. Try: pdf, docx, zip, png, etc.",
                }
            ),
            400,
        )

    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return jsonify({"success": False, "message": f"❌ {error_msg}"}), 400

    try:
        app.logger.info("Upload started: %s", file.filename)

        original_filename = secure_filename(file.filename)
        if not original_filename:
            return jsonify({"success": False, "message": "❌ Invalid filename."}), 400

        file_data = file.read()
        app.logger.info("File read: %d bytes", len(file_data))

        # Check size (redundant to configured limit but good practice)
        if len(file_data) > app.config["MAX_CONTENT_LENGTH"]:
            return jsonify({"success": False, "message": "❌ File too large"}), 413

        app.logger.info("Starting encryption...")
        encrypted_data = encrypt_file(file_data, password)
        app.logger.info("Encryption complete: %d bytes", len(encrypted_data))

        # Generate a unique filename for storage in DB (e.g., UUID.enc)
        # This will be the file_id in the database
        enc_filename = f"{uuid.uuid4().hex}.enc"

        # Create metadata with share token and expiry
        metadata = create_metadata(original_filename)  # Use original name for display

        # Save to Database
        app.logger.info("Saving to database: %s", enc_filename)
        database.save_file(enc_filename, encrypted_data, metadata)
        app.logger.info("Database save complete!")

        return jsonify(
            {
                "success": True,
                "message": f"✅ File uploaded! Expires in {FILE_EXPIRY_DAYS} days.",
                "filename": original_filename,  # Return original name for display
                "file_id": enc_filename.replace(
                    ".enc", ""
                ),  # For email package download
                "share_token": metadata["share_token"],
                "share_url": f"{request.host_url}share/{metadata['share_token']}",
            }
        )
    except Exception as e:
        app.logger.error(
            "Upload error at line %d: %s: %s",
            e.__traceback__.tb_lineno,
            type(e).__name__,
            e,
        )
        import traceback

        app.logger.error(traceback.format_exc())
        return (
            jsonify({"success": False, "message": f"❌ Upload failed: {str(e)}"}),
            500,
        )


@app.route("/share/<token>")
def share_page(token):
    """Render a share page for a specific file."""
    filename, metadata = find_file_by_share_token(token)

    if not filename or not metadata:
        # Token not found - could be invalid or never existed
        return render_template("expired.html", reason="notfound"), 404

    # Check if manually deleted
    if metadata.get("deleted_at"):
        return render_template("expired.html", reason="deleted"), 410

    if is_file_expired(metadata):
        # Clean up expired file from DB
        try:
            database.delete_file(filename)
        except Exception:
            pass
        return render_template("expired.html", reason="expired"), 410  # Gone

    time_remaining = get_time_remaining(metadata)

    return render_template(
        "share.html",
        filename=metadata["original_name"],
        time_remaining=time_remaining,
        downloads=metadata.get("downloads", 0),
        token=token,
    )


@app.route("/api/download/<token>", methods=["POST"])
@limiter.limit("20 per hour", error_message="Too many downloads. Please wait.")
@limiter.limit(
    "5 per minute", error_message="Please wait a moment before downloading again."
)
def download_file(token):
    """Handle file download with decryption."""
    password = request.json.get("password")

    if not password:
        return jsonify({"success": False, "message": "❌ Password required."}), 400

    # Find file by token
    filename, metadata = database.find_by_token(token)

    if not filename or not metadata:
        return (
            jsonify({"success": False, "message": "❌ File not found or expired."}),
            404,
        )

    if metadata.get("deleted_at"):
        return (
            jsonify(
                {"success": False, "message": "❌ File has been deleted by the owner."}
            ),
            410,
        )

    if is_file_expired(metadata):
        # Trigger cleanup
        try:
            database.delete_file(filename)
        except Exception:
            pass
        return (
            jsonify(
                {
                    "success": False,
                    "message": "❌ This file has expired and been deleted.",
                }
            ),
            410,
        )

    try:
        # Get encrypted data from DB
        encrypted_data, _ = database.get_file(filename)

        if not encrypted_data:
            return (
                jsonify({"success": False, "message": "❌ File content missing."}),
                404,
            )

        decrypted_data = decrypt_file(encrypted_data, password)

        # Increment download counter
        increment_download_count(filename)

        return send_file(
            BytesIO(decrypted_data),
            download_name=metadata["original_name"],
            as_attachment=True,
            mimetype="application/octet-stream",  # Generic binary type
        )
    except ValueError:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "❌ Decryption failed. Check your password.",
                }
            ),
            403,
        )
    except Exception as e:
        app.logger.error("Download error: %s", e)
        return (
            jsonify(
                {"success": False, "message": "❌ An error occurred during download."}
            ),
            500,
        )


@app.route("/api/files", methods=["GET"])
def list_files():
    """List all encrypted files with metadata."""
    global _last_cleanup_time, _cleanup_lock

    try:
        # Trigger expired cleanup (throttled to once per minute)
        now = datetime.utcnow()
        if (now - _last_cleanup_time).total_seconds() > 60:
            # Simple non-blocking check to avoid race conditions slowing down requests
            # If another thread is cleaning, we skip
            if not _cleanup_lock:
                _cleanup_lock = True
                try:
                    database.cleanup_expired()
                    _last_cleanup_time = now
                finally:
                    _cleanup_lock = False

        files = []
        # Get all files from DB (now includes _file_size from LENGTH() query)
        db_files = database.list_files()

        for file_id, metadata in db_files:
            if not metadata:
                continue

            # Use pre-calculated file size from database query (no N+1!)
            file_size = metadata.pop("_file_size", 0)

            file_info = {
                "name": metadata.get("original_name", "Unknown"),
                "file_id": file_id.replace(".enc", ""),
                "size": file_size,
                "modified": 0,
                "downloads": metadata.get("downloads", 0),
                "expires_in": get_time_remaining(metadata),
                # NOTE: share_token intentionally NOT exposed in public API
                # Share links shown only to file owner in upload response
            }
            files.append(file_info)

        # Sort by expiry time (most remaining time first)
        files.sort(key=lambda x: x["expires_in"], reverse=True)

        return jsonify({"success": True, "files": files})
    except Exception as e:
        app.logger.error("List files error: %s", e)
        return (
            jsonify({"success": False, "message": "❌ Could not retrieve file list."}),
            500,
        )


@app.route("/api/files/<file_id>", methods=["DELETE", "POST"])
def delete_file(file_id):
    """Delete an encrypted file and its metadata (requires password)."""
    # file_id comes from the UI list "file_id" field.
    # We stripped .enc in list_files, so we add it back to get the actual DB filename.
    if not file_id.endswith(".enc"):
        file_id += ".enc"

    password = ""
    if request.is_json:
        password = request.json.get("password", "")
    else:
        password = request.form.get("password", "")

    if not password:
        return (
            jsonify(
                {"success": False, "message": "❌ Password required to delete file."}
            ),
            400,
        )

    # Retrieve from DB
    encrypted_data, _ = database.get_file(file_id)

    if not encrypted_data:
        return jsonify({"success": False, "message": "❌ File not found."}), 404

    try:
        # Verify password by attempting to decrypt
        decrypt_file(encrypted_data, password)

        # If successful, soft delete (mark as deleted, clear data)
        database.mark_as_deleted(file_id)

        return jsonify({"success": True, "message": "✅ File deleted successfully."})

    except ValueError:
        return (
            jsonify(
                {"success": False, "message": "❌ Incorrect password. Deletion denied."}
            ),
            403,
        )
    except Exception as e:
        app.logger.error("Delete error: %s", e)
        return jsonify({"success": False, "message": "❌ Could not delete file."}), 500


@app.route("/api/download-package/<file_id>", methods=["POST"])
@limiter.limit("10 per hour", error_message="Too many package downloads. Please wait.")
def download_package(file_id):
    """Generate a self-decrypting HTML package for email sharing."""
    import base64

    # Normalize file_id
    if not file_id.endswith(".enc"):
        file_id += ".enc"

    password = ""
    if request.is_json:
        password = request.json.get("password", "")
    else:
        password = request.form.get("password", "")

    if not password:
        return jsonify({"success": False, "message": "❌ Password required."}), 400

    # Get file from database
    encrypted_data, metadata = database.get_file(file_id)

    if not encrypted_data or not metadata:
        return jsonify({"success": False, "message": "❌ File not found."}), 404

    if metadata.get("deleted_at"):
        return jsonify({"success": False, "message": "❌ File has been deleted."}), 410

    if is_file_expired(metadata):
        return jsonify({"success": False, "message": "❌ File has expired."}), 410

    try:
        # Decrypt with original password (validates it)
        decrypted_data = decrypt_file(encrypted_data, password)

        # Re-encrypt with AES-GCM for browser Web Crypto API compatibility
        # IMPORTANT: Use SHA256 for PBKDF2 to match JavaScript's Web Crypto API
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(decrypted_data)

        # Combine ciphertext + tag for GCM (tag appended as per Web Crypto standard)
        encrypted_for_browser = ciphertext + tag

        # Encode to base64
        encrypted_b64 = base64.b64encode(encrypted_for_browser).decode("utf-8")
        salt_b64 = base64.b64encode(salt).decode("utf-8")
        iv_b64 = base64.b64encode(cipher.nonce).decode("utf-8")

        # Load template and replace placeholders
        template_path = os.path.join(
            app.root_path, "templates", "self_decrypt_template.html"
        )
        with open(template_path, "r", encoding="utf-8") as f:
            html_template = f.read()

        original_filename = metadata.get("original_name", "decrypted_file")

        # Compute integrity hash for tamper detection
        import hashlib

        integrity_data = (encrypted_b64 + salt_b64 + iv_b64 + original_filename).encode(
            "utf-8"
        )
        integrity_hash = hashlib.sha256(integrity_data).hexdigest()

        # Escape filename for safe embedding in JavaScript string
        # Prevents XSS if filename contains quotes or HTML
        import html
        safe_filename = html.escape(original_filename).replace("'", "\\'")

        html_content = html_template.replace("{{ENCRYPTED_DATA}}", encrypted_b64)
        html_content = html_content.replace("{{SALT}}", salt_b64)
        html_content = html_content.replace("{{IV}}", iv_b64)
        html_content = html_content.replace("{{FILENAME}}", safe_filename)
        html_content = html_content.replace("{{INTEGRITY_HASH}}", integrity_hash)

        # Create downloadable HTML file
        safe_name = secure_filename(original_filename.rsplit(".", 1)[0])
        download_filename = f"{safe_name}_encrypted.html"

        # Increment download counter (email packages count as downloads too)
        increment_download_count(file_id)

        return send_file(
            BytesIO(html_content.encode("utf-8")),
            download_name=download_filename,
            as_attachment=True,
            mimetype="text/html",
        )

    except ValueError:
        return jsonify({"success": False, "message": "❌ Incorrect password."}), 403
    except Exception as e:
        app.logger.error("Package generation error: %s", e)
        return (
            jsonify({"success": False, "message": "❌ Could not generate package."}),
            500,
        )


@app.errorhandler(413)
def request_entity_too_large(_error):
    """Handle file too large error."""
    max_size_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    return (
        jsonify(
            {
                "success": False,
                "message": f"❌ File too large. Maximum size is {max_size_mb}MB.",
            }
        ),
        413,
    )


@app.errorhandler(429)
def rate_limit_exceeded(_error):
    """Handle rate limit exceeded error."""
    return (
        jsonify(
            {"success": False, "message": "❌ Too many requests. Please slow down."}
        ),
        429,
    )


@app.errorhandler(410)
def gone(_error):
    """Handle expired resource error."""
    return render_template("expired.html", reason="expired"), 410


@app.errorhandler(500)
def internal_error(_error):
    """Handle internal server errors with JSON."""
    return (
        jsonify({"success": False, "message": "❌ Internal Server Error. Check logs."}),
        500,
    )


@app.route("/health")
def health_check():
    """Check database connection status."""
    try:
        # Simple query to check DB
        with database.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return jsonify({"status": "healthy", "database": "connected"}), 200
    except Exception as e:
        app.logger.error("Health check failed: %s", e)
        return jsonify({"status": "unhealthy", "database": str(e)}), 500


@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    # Strict-Transport-Security: Ensure HTTPS (1 year)
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )

    # X-Content-Type-Options: Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # X-Frame-Options: Prevent clickjacking (deny all framing)
    response.headers["X-Frame-Options"] = "DENY"

    # X-XSS-Protection: Enable XSS filter (browser default but good to have)
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Referrer-Policy: Control referrer information
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Content-Security-Policy: Restrict resources to own origin + trusted CDNs
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )

    return response


if __name__ == "__main__":
    app.run(debug=config.DEBUG, host="127.0.0.1", port=5000)

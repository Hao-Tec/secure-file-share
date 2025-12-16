"""Secure File Share - Flask Application with AES Encryption."""
import os
import re
from flask import Flask, request, render_template, send_file, jsonify
from flask_wtf.csrf import CSRFProtect
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

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Constants for encryption
SALT_LENGTH = 16  # 16 bytes = 128 bits
NONCE_LENGTH = 16
TAG_LENGTH = 16


def validate_password(password: str) -> tuple[bool, str]:
    """Validate password meets security requirements.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
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
        return True  # Allow files without extension
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in config.ALLOWED_EXTENSIONS


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 128-bit key from password and salt using PBKDF2."""
    return PBKDF2(password, salt, dkLen=16, count=100000)


def encrypt_file(file_data: bytes, password: str) -> bytes:
    """Encrypt file data using AES-EAX mode with a unique salt.
    
    Output format: salt (16 bytes) + nonce (16 bytes) + tag (16 bytes) + ciphertext
    """
    # Generate unique salt for this file
    salt = get_random_bytes(SALT_LENGTH)
    key = derive_key(password, salt)
    
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    
    # Prepend salt, nonce, and tag to ciphertext
    return salt + cipher.nonce + tag + ciphertext


def decrypt_file(file_data: bytes, password: str) -> bytes:
    """Decrypt file data that was encrypted with encrypt_file().
    
    Input format: salt (16 bytes) + nonce (16 bytes) + tag (16 bytes) + ciphertext
    """
    # Extract components
    salt = file_data[:SALT_LENGTH]
    nonce = file_data[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
    tag = file_data[SALT_LENGTH + NONCE_LENGTH:SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH]
    ciphertext = file_data[SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH:]
    
    # Derive key using the file's salt
    key = derive_key(password, salt)
    
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


@app.route("/")
def index():
    """Render the main page."""
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    """Handle file upload with encryption."""
    # Check if file is in request
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "❌ No file provided."}), 400
    
    file = request.files["file"]
    password = request.form.get("password", "")
    
    # Validate file
    if not file or file.filename == '':
        return jsonify({"success": False, "message": "❌ No file selected."}), 400
    
    if not allowed_file(file.filename):
        return jsonify({
            "success": False, 
            "message": "❌ File type not allowed."
        }), 400
    
    # Validate password
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        return jsonify({"success": False, "message": f"❌ {error_msg}"}), 400
    
    try:
        filename = secure_filename(file.filename)
        if not filename:
            return jsonify({
                "success": False, 
                "message": "❌ Invalid filename."
            }), 400
            
        file_data = file.read()
        encrypted_data = encrypt_file(file_data, password)
        
        enc_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + ".enc")
        with open(enc_path, "wb") as f:
            f.write(encrypted_data)
        
        return jsonify({
            "success": True,
            "message": "✅ File uploaded and encrypted successfully!",
            "filename": filename
        })
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return jsonify({
            "success": False, 
            "message": "❌ An error occurred during upload."
        }), 500


@app.route("/download", methods=["POST"])
def download():
    """Handle file download with decryption."""
    filename = request.form.get("filename", "")
    password = request.form.get("password", "")
    
    if not filename or not password:
        return jsonify({
            "success": False, 
            "message": "❌ Filename and password are required."
        }), 400
    
    # Sanitize filename to prevent path traversal
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return jsonify({
            "success": False, 
            "message": "❌ Invalid filename."
        }), 400
    
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename + ".enc")
    
    if not os.path.exists(enc_path):
        return jsonify({
            "success": False, 
            "message": "❌ Encrypted file not found."
        }), 404
    
    try:
        with open(enc_path, "rb") as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data, password)
        
        return send_file(
            BytesIO(decrypted_data),
            download_name=safe_filename,
            as_attachment=True
        )
    except ValueError:
        # Decryption failed - wrong password or corrupted file
        return jsonify({
            "success": False,
            "message": "❌ Decryption failed. Check your password and try again."
        }), 400
    except Exception as e:
        app.logger.error(f"Download error: {e}")
        return jsonify({
            "success": False,
            "message": "❌ An error occurred during download."
        }), 500


@app.route("/api/files", methods=["GET"])
def list_files():
    """List all encrypted files."""
    try:
        files = []
        upload_folder = app.config['UPLOAD_FOLDER']
        
        for filename in os.listdir(upload_folder):
            if filename.endswith(".enc"):
                filepath = os.path.join(upload_folder, filename)
                stat = os.stat(filepath)
                
                # Remove .enc extension for display
                display_name = filename[:-4]
                
                files.append({
                    "name": display_name,
                    "size": stat.st_size,
                    "modified": stat.st_mtime
                })
        
        # Sort by modification time (newest first)
        files.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({"success": True, "files": files})
    except Exception as e:
        app.logger.error(f"List files error: {e}")
        return jsonify({
            "success": False, 
            "message": "❌ Could not retrieve file list."
        }), 500


@app.route("/api/files/<filename>", methods=["DELETE"])
def delete_file(filename):
    """Delete an encrypted file."""
    # Sanitize filename
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return jsonify({
            "success": False, 
            "message": "❌ Invalid filename."
        }), 400
    
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename + ".enc")
    
    if not os.path.exists(enc_path):
        return jsonify({
            "success": False, 
            "message": "❌ File not found."
        }), 404
    
    try:
        os.remove(enc_path)
        return jsonify({
            "success": True,
            "message": "✅ File deleted successfully."
        })
    except Exception as e:
        app.logger.error(f"Delete error: {e}")
        return jsonify({
            "success": False,
            "message": "❌ Could not delete file."
        }), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    max_size_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
    return jsonify({
        "success": False,
        "message": f"❌ File too large. Maximum size is {max_size_mb}MB."
    }), 413


if __name__ == "__main__":
    # Use config.DEBUG instead of hardcoded debug=True
    app.run(debug=config.DEBUG, host='127.0.0.1', port=5000)

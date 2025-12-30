"""Configuration settings for the Secure File Share application."""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Base configuration class."""

    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-fallback-key-change-in-production"
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size
    ALLOWED_EXTENSIONS = {
        # Documents
        "txt",
        "pdf",
        "doc",
        "docx",
        "odt",
        "rtf",
        "xls",
        "xlsx",
        "csv",
        "ppt",
        "pptx",
        # Code files
        "py",
        "js",
        "ts",
        "html",
        "htm",
        "css",
        "scss",
        "sass",
        "json",
        "xml",
        "yaml",
        "yml",
        "md",
        "markdown",
        "java",
        "c",
        "cpp",
        "h",
        "hpp",
        "cs",
        "go",
        "rs",
        "rb",
        "php",
        "sql",
        "sh",
        "bash",
        "ps1",
        "bat",
        "cmd",
        # Images
        "png",
        "jpg",
        "jpeg",
        "gif",
        "bmp",
        "webp",
        "svg",
        "ico",
        # Archives
        "zip",
        "rar",
        "7z",
        "tar",
        "gz",
        "bz2",
        "xz",
        # Media
        "mp3",
        "mp4",
        "mkv",
        "avi",
        "mov",
        "wmv",
        "flv",
        "webm",
        "wav",
        "flac",
        "aac",
        "ogg",
        # Other common types
        "log",
        "ini",
        "cfg",
        "conf",
        "env",
        "bak",
    }
    # Security settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour CSRF token validity
    # Password requirements
    MIN_PASSWORD_LENGTH = 8


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False

    # Security: Enforce secure cookies in production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # In production, SECRET_KEY MUST be set via environment variable (enforced in get_config)


def get_config():
    """Return the appropriate configuration based on environment."""
    env = os.environ.get("FLASK_ENV", "development")
    if env == "production":
        # Critical Security Check: Ensure SECRET_KEY is set in production
        if not os.environ.get("SECRET_KEY"):
            raise ValueError("CRITICAL: SECRET_KEY environment variable must be set in production mode!")

        return ProductionConfig()
    return DevelopmentConfig()

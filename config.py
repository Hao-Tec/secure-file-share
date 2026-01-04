"""Configuration settings for Cipher Vault."""

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

    # Session Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Password requirements
    MIN_PASSWORD_LENGTH = 8


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False

    # In production, require secure cookies
    SESSION_COOKIE_SECURE = True

    # In production, SECRET_KEY MUST be set via environment variable
    def __init__(self):
        super().__init__()
        # Check if SECRET_KEY is the default/fallback value or missing
        # Note: self.SECRET_KEY is inherited from Config class attribute if not overridden
        # But here we are checking the class attribute or the instance attribute.
        # Since Config.SECRET_KEY is calculated at module level, we check that.

        # We need to re-check os.environ because Config.SECRET_KEY was set at import time
        # If the env var was set AFTER import (unlikely in real prod, but possible in tests),
        # we should respect that.

        env_secret = os.environ.get("SECRET_KEY")

        if not env_secret or env_secret == "dev-fallback-key-change-in-production":
             raise ValueError("SECRET_KEY environment variable must be set to a secure value in production!")


def get_config():
    """Return the appropriate configuration based on environment."""
    env = os.environ.get("FLASK_ENV", "development")
    if env == "production":
        return ProductionConfig()
    return DevelopmentConfig()

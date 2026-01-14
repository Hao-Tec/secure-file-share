"""Database operations for secure file storage with PostgreSQL."""
import os
import json
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any

import psycopg2
from psycopg2.extras import RealDictCursor

# Global DB connection string
DATABASE_URL = os.environ.get("DATABASE_URL")


@contextmanager
def db_cursor():
    """Context manager for database operations with auto commit/rollback."""
    if not DATABASE_URL and not os.environ.get("DATABASE_URL"):
        raise ValueError("DATABASE_URL environment variable is not set")

    # Re-fetch in case it was set after import (for tests)
    conn_str = DATABASE_URL or os.environ.get("DATABASE_URL")

    conn = psycopg2.connect(conn_str, cursor_factory=RealDictCursor)
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def get_db_connection():
    """Establish a connection to the PostgreSQL database.

    Note: Prefer using db_cursor() context manager for most operations.
    This function is kept for compatibility with health checks.
    """
    conn_str = DATABASE_URL or os.environ.get("DATABASE_URL")
    if not conn_str:
        raise ValueError("DATABASE_URL environment variable is not set")
    return psycopg2.connect(conn_str, cursor_factory=RealDictCursor)


# Shared schema - can be imported by reset_db.py
SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS encrypted_files (
        id SERIAL PRIMARY KEY,
        file_id VARCHAR(255) UNIQUE NOT NULL,
        filename VARCHAR(255) NOT NULL,
        encrypted_data BYTEA NOT NULL,
        metadata JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_file_id ON encrypted_files(file_id);
    CREATE INDEX IF NOT EXISTS idx_share_token ON encrypted_files((metadata->>'share_token'));
    CREATE INDEX IF NOT EXISTS idx_expires_at ON encrypted_files((metadata->>'expires_at'));
"""


def init_db() -> None:
    """Initialize the database schema."""
    if not DATABASE_URL and not os.environ.get("DATABASE_URL"):
        return

    with db_cursor() as cur:
        cur.execute(SCHEMA_SQL)


def save_file(filename: str, encrypted_data: bytes, metadata: Dict[str, Any]) -> bool:
    """Save an encrypted file and its metadata to the database."""
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO encrypted_files (file_id, filename, encrypted_data, metadata)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (file_id)
            DO UPDATE SET
                encrypted_data = EXCLUDED.encrypted_data,
                metadata = EXCLUDED.metadata,
                created_at = CURRENT_TIMESTAMP;
        """, (filename, filename, psycopg2.Binary(encrypted_data), json.dumps(metadata)))
    return True


def get_file(filename: str) -> Tuple[Optional[bytes], Optional[Dict[str, Any]]]:
    """Retrieve an encrypted file and its metadata by filename."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT encrypted_data, metadata
            FROM encrypted_files
            WHERE file_id = %s
        """, (filename,))

        result = cur.fetchone()
        if result:
            data = bytes(result['encrypted_data'])
            return data, result['metadata']
    return None, None


def get_metadata(filename: str) -> Optional[Dict[str, Any]]:
    """Retrieve just the metadata for a file (faster than getting full content)."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT metadata
            FROM encrypted_files
            WHERE file_id = %s
        """, (filename,))

        result = cur.fetchone()
        if result:
            return result['metadata']
    return None


def delete_file(filename: str) -> bool:
    """Hard delete a file from the database (used for expired files)."""
    with db_cursor() as cur:
        cur.execute("DELETE FROM encrypted_files WHERE file_id = %s", (filename,))
    return True


def mark_as_deleted(filename: str) -> bool:
    """Soft delete: Clear data to save space, but keep metadata with deleted flag."""
    with db_cursor() as cur:
        cur.execute("""
            UPDATE encrypted_files
            SET encrypted_data = %s,
                metadata = metadata || jsonb_build_object('deleted_at', to_json(CURRENT_TIMESTAMP)::text)
            WHERE file_id = %s
        """, (psycopg2.Binary(b''), filename))
    return True


def list_files() -> List[Tuple[str, Dict[str, Any]]]:
    """List all ACTIVE files with their sizes. Excludes soft-deleted files."""
    with db_cursor() as cur:
        # Include LENGTH() to avoid N+1 query for file sizes
        # Sort by expires_at DESC (most time remaining first) at DB level
        cur.execute("""
            SELECT file_id, metadata, LENGTH(encrypted_data) as file_size
            FROM encrypted_files
            WHERE NOT (metadata ? 'deleted_at')
            ORDER BY metadata->>'expires_at' DESC
        """)
        results = cur.fetchall()
        # Return file_id, metadata with size embedded
        files = []
        for row in results:
            metadata = row['metadata']
            metadata['_file_size'] = row['file_size']
            files.append((row['file_id'], metadata))
        return files


def find_by_token(token: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Find a file by its share token (includes deleted files for status messages)."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT file_id, metadata
            FROM encrypted_files
            WHERE metadata->>'share_token' = %s
        """, (token,))

        result = cur.fetchone()
        if result:
            return result['file_id'], result['metadata']
    return None, None


def cleanup_expired() -> int:
    """Remove expired files from the database."""
    with db_cursor() as cur:
        now = datetime.utcnow().isoformat() + "Z"
        cur.execute("""
            DELETE FROM encrypted_files
            WHERE metadata->>'expires_at' < %s
        """, (now,))
        return cur.rowcount


def update_metadata(filename: str, updates: Dict[str, Any]) -> bool:
    """Update metadata fields (e.g. downloads count)."""
    with db_cursor() as cur:
        # Use FOR UPDATE to lock the row during update
        cur.execute(
            "SELECT metadata FROM encrypted_files WHERE file_id = %s FOR UPDATE",
            (filename,)
        )
        result = cur.fetchone()

        if result:
            meta = result['metadata']
            meta.update(updates)

            cur.execute("""
                UPDATE encrypted_files
                SET metadata = %s
                WHERE file_id = %s
            """, (json.dumps(meta), filename))
            return True
    return False

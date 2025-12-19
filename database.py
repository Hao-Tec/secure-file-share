import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Global DB connection string
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    """Establish a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        # Fallback for local testing if needed, or raise error
        raise ValueError("DATABASE_URL environment variable is not set")
    
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    """Initialize the database schema."""
    if not DATABASE_URL:
        return

    conn = get_db_connection()
    cur = conn.cursor()
    
    # Create table if not exists
    # We store:
    # - file_id: Unique identifier (filename or token)
    # - filename: Original filename (encrypted name usually)
    # - encrypted_data: The actual file bytes (BYTEA)
    # - metadata: The JSON metadata (JSONB)
    cur.execute("""
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
    """)
    
    conn.commit()
    cur.close()
    conn.close()

def save_file(filename, encrypted_data, metadata):
    """Save an encrypted file and its metadata to the database."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # file_id is the unique filename we usually use (e.g., uuid.enc)
        cur.execute("""
            INSERT INTO encrypted_files (file_id, filename, encrypted_data, metadata)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (file_id) 
            DO UPDATE SET 
                encrypted_data = EXCLUDED.encrypted_data,
                metadata = EXCLUDED.metadata,
                created_at = CURRENT_TIMESTAMP;
        """, (filename, filename, psycopg2.Binary(encrypted_data), json.dumps(metadata)))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"DB Save Error: {e}")
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()

def get_file(filename):
    """Retrieve an encrypted file and its metadata by filename."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT encrypted_data, metadata 
            FROM encrypted_files 
            WHERE file_id = %s
        """, (filename,))
        
        result = cur.fetchone()
        if result:
            # psycopg2 returns memoryview or bytes for BYTEA
            data = bytes(result['encrypted_data'])
            metadata = result['metadata']
            return data, metadata
        return None, None
    finally:
        cur.close()
        conn.close()

def get_metadata(filename):
    """Retrieve just the metadata for a file (faster than getting full content)."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT metadata 
            FROM encrypted_files 
            WHERE file_id = %s
        """, (filename,))
        
        result = cur.fetchone()
        if result:
            return result['metadata']
        return None
    finally:
        cur.close()
        conn.close()

def delete_file(filename):
    """Delete a file from the database."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("DELETE FROM encrypted_files WHERE file_id = %s", (filename,))
        conn.commit()
        return True
    finally:
        cur.close()
        conn.close()

def list_files():
    """List all files returning (filename, metadata)."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT file_id, metadata FROM encrypted_files")
        results = cur.fetchall()
        return [(r['file_id'], r['metadata']) for r in results]
    finally:
        cur.close()
        conn.close()

def find_by_token(token):
    """Find a file by its share token."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Use the JSONB index for checking share_token
        cur.execute("""
            SELECT file_id, metadata 
            FROM encrypted_files 
            WHERE metadata->>'share_token' = %s
        """, (token,))
        
        result = cur.fetchone()
        if result:
            return result['file_id'], result['metadata']
        return None, None
    finally:
        cur.close()
        conn.close()

def cleanup_expired():
    """Remove expired files from the database."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Find expired files based on metadata expires_at
        now = datetime.utcnow().isoformat() + "Z"
        
        # We can do this in SQL efficiently
        cur.execute("""
            DELETE FROM encrypted_files 
            WHERE metadata->>'expires_at' < %s
        """, (now,))
        
        deleted_count = cur.rowcount
        conn.commit()
        return deleted_count
    finally:
        cur.close()
        conn.close()

def update_metadata(filename, updates):
    """Update metadata fields (e.g. downloads count)."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # We need to fetch, update, and save back because JSONB partial updates 
        # can be complex depending on Postgres version, software usage is safer.
        # OR use jsonb_set for specific fields if simple.
        # For safety and "updates" dict merging, let's do fetch-merge-save 
        # inside a transaction.
        
        cur.execute("SELECT metadata FROM encrypted_files WHERE file_id = %s FOR UPDATE", (filename,))
        result = cur.fetchone()
        
        if result:
            meta = result['metadata']
            meta.update(updates)
            
            cur.execute("""
                UPDATE encrypted_files 
                SET metadata = %s 
                WHERE file_id = %s
            """, (json.dumps(meta), filename))
            
            conn.commit()
            return True
        return False
    except Exception:
        conn.rollback()
        return False
    finally:
        cur.close()
        conn.close()

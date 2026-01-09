"""
Share Link Manager for ShareCLI
Handles creation, validation, and management of temporary share links.
"""

import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
import threading
import os

class ShareLinkManager:
    """Manages temporary share links with expiry and download limits."""
    
    def __init__(self, db_path='share_links.db'):
        """Initialize the share link manager with SQLite database."""
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Create the share_links table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS share_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT UNIQUE NOT NULL,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL,
                    max_downloads INTEGER DEFAULT 0,
                    download_count INTEGER DEFAULT 0,
                    pin_hash TEXT,
                    creator_ip TEXT,
                    last_accessed_at DATETIME,
                    revoked INTEGER DEFAULT 0
                )
            ''')
            conn.commit()
    
    def generate_share_link(self, file_path, expiry_hours=24, max_downloads=0, pin=None, creator_ip=None):
        """
        Generate a new share link for a file.
        
        Args:
            file_path: Absolute path to the file
            expiry_hours: Hours until link expires (default: 24)
            max_downloads: Maximum downloads (0 = unlimited)
            pin: Optional PIN for protection (4-6 digits)
            creator_ip: IP address of link creator
            
        Returns:
            dict: Share link information including token
        """
        # Generate secure random token
        token = secrets.token_urlsafe(24)  # ~32 characters
        
        # Calculate expiry time
        expires_at = datetime.now() + timedelta(hours=expiry_hours)
        
        # Hash PIN if provided
        pin_hash = None
        if pin:
            pin_hash = hashlib.sha256(str(pin).encode()).hexdigest()
        
        # Get file name
        file_name = os.path.basename(file_path)
        
        # Insert into database
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO share_links 
                    (token, file_path, file_name, expires_at, max_downloads, pin_hash, creator_ip)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (token, file_path, file_name, expires_at.isoformat(), max_downloads, pin_hash, creator_ip))
                conn.commit()
        
        return {
            'token': token,
            'file_name': file_name,
            'expires_at': expires_at.isoformat(),
            'max_downloads': max_downloads,
            'has_pin': pin is not None
        }
    
    def validate_link(self, token, pin=None):
        """
        Validate a share link token.
        
        Args:
            token: Share link token
            pin: Optional PIN if link is protected
            
        Returns:
            dict: Link info if valid, None otherwise
        """
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM share_links WHERE token = ? AND revoked = 0
                ''', (token,))
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                # Check if expired
                expires_at = datetime.fromisoformat(row['expires_at'])
                if datetime.now() > expires_at:
                    return None
                
                # Check download limit
                if row['max_downloads'] > 0 and row['download_count'] >= row['max_downloads']:
                    return None
                
                # Check PIN if required
                if row['pin_hash']:
                    if not pin:
                        return {'requires_pin': True, 'file_name': row['file_name']}
                    
                    pin_hash = hashlib.sha256(str(pin).encode()).hexdigest()
                    if pin_hash != row['pin_hash']:
                        return {'pin_invalid': True}
                
                # Valid link
                return {
                    'file_path': row['file_path'],
                    'file_name': row['file_name'],
                    'download_count': row['download_count'],
                    'max_downloads': row['max_downloads']
                }
    
    def increment_download(self, token):
        """Increment the download counter for a link."""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE share_links 
                    SET download_count = download_count + 1,
                        last_accessed_at = CURRENT_TIMESTAMP
                    WHERE token = ?
                ''', (token,))
                conn.commit()
                
                # Check if should auto-revoke (one-time download)
                cursor = conn.execute('''
                    SELECT max_downloads, download_count FROM share_links WHERE token = ?
                ''', (token,))
                row = cursor.fetchone()
                
                if row and row[0] > 0 and row[1] >= row[0]:
                    # Auto-revoke after reaching download limit
                    conn.execute('UPDATE share_links SET revoked = 1 WHERE token = ?', (token,))
                    conn.commit()
    
    def list_active_links(self):
        """
        List all active (non-expired, non-revoked) share links.
        
        Returns:
            list: Active share links
        """
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT 
                        token, file_name, created_at, expires_at, 
                        max_downloads, download_count, last_accessed_at
                    FROM share_links 
                    WHERE revoked = 0 AND datetime(expires_at) > datetime('now')
                    ORDER BY created_at DESC
                ''')
                
                links = []
                for row in cursor:
                    links.append({
                        'token': row['token'],
                        'file_name': row['file_name'],
                        'created_at': row['created_at'],
                        'expires_at': row['expires_at'],
                        'max_downloads': row['max_downloads'],
                        'download_count': row['download_count'],
                        'last_accessed_at': row['last_accessed_at']
                    })
                
                return links
    
    def revoke_link(self, token):
        """
        Revoke a share link (mark as invalid).
        
        Args:
            token: Share link token to revoke
            
        Returns:
            bool: True if successfully revoked
        """
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    UPDATE share_links SET revoked = 1 WHERE token = ?
                ''', (token,))
                conn.commit()
                return cursor.rowcount > 0
    
    def cleanup_expired(self):
        """
        Delete expired share links from database.
        Should be called periodically (e.g., daily).
        
        Returns:
            int: Number of links deleted
        """
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                # Delete links expired more than 7 days ago
                cutoff = datetime.now() - timedelta(days=7)
                cursor = conn.execute('''
                    DELETE FROM share_links 
                    WHERE datetime(expires_at) < datetime(?)
                ''', (cutoff.isoformat(),))
                conn.commit()
                return cursor.rowcount
    
    def get_link_stats(self, token):
        """Get statistics for a specific share link."""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM share_links WHERE token = ?
                ''', (token,))
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                return dict(row)


# Global instance
_share_manager = None

def get_share_manager():
    """Get or create the global share manager instance."""
    global _share_manager
    if _share_manager is None:
        _share_manager = ShareLinkManager()
    return _share_manager

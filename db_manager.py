import sqlite3
import os
import secrets
import time
from typing import Optional, List, Tuple


class DatabaseManager:
    """Quản lý lưu trữ mật khẩu đã mã hóa bằng SQLite"""

    def __init__(self, db_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_path = db_path or os.path.join(base_dir, 'aes_manager.db')
        self._conn: Optional[sqlite3.Connection] = None

    def initialize(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                iterations INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                data BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                access_mode TEXT NOT NULL DEFAULT 'owner_only',
                UNIQUE(owner_user_id, filename)
            );
            """
        )
        # Đảm bảo cột access_mode tồn tại nếu DB cũ
        try:
            cur = self._conn.execute("PRAGMA table_info(resources)")
            cols = [r[1] for r in cur.fetchall()]
            if 'access_mode' not in cols:
                self._conn.execute("ALTER TABLE resources ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'owner_only'")
                self._conn.commit()
        except sqlite3.Error:
            pass
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                grantee_user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(owner_user_id, filename, grantee_user_id)
            );
            """
        )
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def store_password_for_file(self, file_path: str, password: str, iterations: int = 200_000) -> bool:
        if not self._conn:
            self.initialize()
        salt = secrets.token_bytes(16)
        # Sử dụng PBKDF2-HMAC-SHA256 từ stdlib để băm mật khẩu
        import hashlib
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)
        ts = int(time.time())
        try:
            self._conn.execute(
                "INSERT INTO passwords(file_path, password_salt, password_hash, iterations, created_at) VALUES (?, ?, ?, ?, ?)",
                (file_path, salt, pwd_hash, iterations, ts)
            )
            self._conn.commit()
            return True
        except sqlite3.Error:
            return False

    def list_passwords(self) -> List[Tuple[int, str, int]]:
        if not self._conn:
            self.initialize()
        cur = self._conn.execute("SELECT id, file_path, created_at FROM passwords ORDER BY created_at DESC")
        return list(cur.fetchall())

    def find_file_by_name(self, file_name: str) -> Optional[str]:
        if not self._conn:
            self.initialize()
        cur = self._conn.execute("SELECT file_path FROM passwords")
        for row in cur.fetchall():
            path = row[0]
            if os.path.basename(path) == file_name:
                return path
        return None

    def create_user(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        if not self._conn:
            self.initialize()
        import secrets, time, hashlib
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000, dklen=32)
        ts = int(time.time())
        try:
            cur = self._conn.execute(
                "INSERT INTO users(username, salt, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, salt, pwd_hash, ts)
            )
            self._conn.commit()
            return True, cur.lastrowid
        except sqlite3.IntegrityError:
            return False, None

    def verify_user(self, username: str, password: str) -> Optional[int]:
        if not self._conn:
            self.initialize()
        import hashlib
        cur = self._conn.execute("SELECT id, salt, password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            return None
        uid, salt, stored = row
        test = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000, dklen=32)
        if test == stored:
            return uid
        return None

    def get_user_id(self, username: str) -> Optional[int]:
        if not self._conn:
            self.initialize()
        cur = self._conn.execute("SELECT id FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            return None
        return int(row[0])

    def store_resource(self, owner_user_id: int, filename: str, data: bytes) -> bool:
        if not self._conn:
            self.initialize()
        import time
        ts = int(time.time())
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO resources(owner_user_id, filename, data, created_at, access_mode) VALUES (?, ?, ?, ?, COALESCE((SELECT access_mode FROM resources WHERE owner_user_id=? AND filename=?),'owner_only'))",
                (owner_user_id, filename, data, ts, owner_user_id, filename)
            )
            self._conn.commit()
            return True
        except sqlite3.Error:
            return False

    def get_resource(self, filename: str) -> Tuple[Optional[int], Optional[bytes]]:
        if not self._conn:
            self.initialize()
        cur = self._conn.execute("SELECT owner_user_id, data FROM resources WHERE filename=?", (filename,))
        row = cur.fetchone()
        if not row:
            return None, None
        return row[0], row[1]

    def get_access_mode(self, filename: str) -> str:
        if not self._conn:
            self.initialize()
        cur = self._conn.execute("SELECT access_mode FROM resources WHERE filename=?", (filename,))
        row = cur.fetchone()
        return row[0] if row and row[0] else 'owner_only'

    def set_access_mode(self, owner_user_id: int, filename: str, mode: str) -> bool:
        if not self._conn:
            self.initialize()
        try:
            self._conn.execute(
                "UPDATE resources SET access_mode=? WHERE owner_user_id=? AND filename=?",
                (mode, owner_user_id, filename)
            )
            self._conn.commit()
            return True
        except sqlite3.Error:
            return False

    def grant_permission(self, owner_user_id: int, filename: str, grantee_user_id: int) -> bool:
        if not self._conn:
            self.initialize()
        import time
        ts = int(time.time())
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO permissions(owner_user_id, filename, grantee_user_id, created_at) VALUES (?, ?, ?, ?)",
                (owner_user_id, filename, grantee_user_id, ts)
            )
            self._conn.commit()
            return True
        except sqlite3.Error:
            return False

    def revoke_permission(self, owner_user_id: int, filename: str, grantee_user_id: int) -> bool:
        if not self._conn:
            self.initialize()
        try:
            self._conn.execute(
                "DELETE FROM permissions WHERE owner_user_id=? AND filename=? AND grantee_user_id=?",
                (owner_user_id, filename, grantee_user_id)
            )
            self._conn.commit()
            return True
        except sqlite3.Error:
            return False

    def has_permission(self, owner_user_id: int, filename: str, grantee_user_id: int) -> bool:
        if not self._conn:
            self.initialize()
        cur = self._conn.execute(
            "SELECT 1 FROM permissions WHERE owner_user_id=? AND filename=? AND grantee_user_id=?",
            (owner_user_id, filename, grantee_user_id)
        )
        return cur.fetchone() is not None


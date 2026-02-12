import sqlite3
from models import User, Message
from datetime import datetime


class SQLiteStorage:
    def __init__(self, db_path="valentine.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            recipient_id INTEGER,
            text TEXT,
            created_at TEXT,
            is_read INTEGER DEFAULT 0
        )
        """)

        self.conn.commit()

    def add_user(self, username, password_hash):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        self.conn.commit()
        user_id = cursor.lastrowid
        return User(user_id, username, password_hash)

    def get_user_by_username(self, username):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return User(row["id"], row["username"], row["password_hash"])

    def get_user_by_id(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return User(row["id"], row["username"], row["password_hash"])

    def add_message(self, sender_id, recipient_id, text):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()

        cursor.execute("""
            INSERT INTO messages (sender_id, recipient_id, text, created_at)
            VALUES (?, ?, ?, ?)
        """, (sender_id, recipient_id, text, now))

        self.conn.commit()
        message_id = cursor.lastrowid

        return Message(
            id=message_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            text=text,
            created_at=datetime.fromisoformat(now),
            is_read=False
        )

    def get_message(self, message_id):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM messages WHERE id = ?",
            (message_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None

        return Message(
            id=row["id"],
            sender_id=row["sender_id"],
            recipient_id=row["recipient_id"],
            text=row["text"],
            created_at=datetime.fromisoformat(row["created_at"]),
            is_read=bool(row["is_read"])
        )

    def get_inbox(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM messages WHERE recipient_id = ?",
            (user_id,)
        )
        rows = cursor.fetchall()

        return [
            Message(
                id=row["id"],
                sender_id=row["sender_id"],
                recipient_id=row["recipient_id"],
                text=row["text"],
                created_at=datetime.fromisoformat(row["created_at"]),
                is_read=bool(row["is_read"])
            )
            for row in rows
        ]

    def get_sent(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM messages WHERE sender_id = ?",
            (user_id,)
        )
        rows = cursor.fetchall()

        return [
            Message(
                id=row["id"],
                sender_id=row["sender_id"],
                recipient_id=row["recipient_id"],
                text=row["text"],
                created_at=datetime.fromisoformat(row["created_at"]),
                is_read=bool(row["is_read"])
            )
            for row in rows
        ]

    def mark_as_read(self, message_id):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE messages SET is_read = 1 WHERE id = ?",
            (message_id,)
        )
        self.conn.commit()

    def update_recipient(self, message_id, new_recipient_id):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE messages SET recipient_id = ? WHERE id = ?",
            (new_recipient_id, message_id)
        )
        self.conn.commit()

    def count_messages(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM messages")
        return cursor.fetchone()[0]

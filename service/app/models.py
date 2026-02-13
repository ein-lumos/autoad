from dataclasses import dataclass
from datetime import datetime

@dataclass
class User:
    id: int
    username: str
    password_hash: str

@dataclass
class Message:
    id: int
    sender_id: int
    recipient_id: int
    text: str
    created_at: datetime
    is_read: bool = False

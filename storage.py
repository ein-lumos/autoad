from typing import Dict
from models import User, Message
from datetime import datetime

class InMemoryStorage:
    def __init__(self):
        self.users: Dict[int, User] = {}
        self.messages: Dict[int, Message] = {}

        self._user_id_seq = 1
        self._message_id_seq = 1

    def add_user(self, username, password_hash):
        user = User(self._user_id_seq, username, password_hash)
        self.users[self._user_id_seq] = user
        self._user_id_seq += 1
        return user

    def get_user_by_username(self, username):
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    def get_user_by_id(self, user_id):
        return self.users.get(user_id)

    def add_message(self, sender_id, recipient_id, text):
        message = Message(
            id=self._message_id_seq,
            sender_id=sender_id,
            recipient_id=recipient_id,
            text=text,
            created_at=datetime.now()
        )
        self.messages[self._message_id_seq] = message
        self._message_id_seq += 1
        return message

    def get_message(self, message_id):
        return self.messages.get(message_id)

    def get_inbox(self, user_id):
        return [m for m in self.messages.values() if m.recipient_id == user_id]

    def get_sent(self, user_id):
        return [m for m in self.messages.values() if m.sender_id == user_id]


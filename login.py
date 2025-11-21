import sys
import sqlite3
import os
import hashlib
import binascii
import secrets
import argparse
import getpass
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    TK_AVAILABLE = True
except Exception:
    tk = None
    ttk = None
    messagebox = None
    TK_AVAILABLE = False
DB_PATH = "users.db"
def create_db(db_path=DB_PATH):
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                pwd_hash TEXT NOT NULL
            )
        ''')
def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200000)
    return binascii.hexlify(salt).decode('ascii'), binascii.hexlify(pwd_hash).decode('ascii')
def verify_password(stored_salt_hex: str, stored_hash_hex: str, provided_password: str) -> bool:
    try:
        salt = binascii.unhexlify(stored_salt_hex.encode('ascii'))
    except Exception:
        return False
    _, new_hash_hex = hash_password(provided_password, salt)
    return secrets.compare_digest(new_hash_hex, stored_hash_hex)
def register_user(username: str, password: str, db_path=DB_PATH):
    username = (username or '').strip()
    if not username or not password:
        return False, "Username and password cannot be empty."
    try:
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            salt_hex, hash_hex = hash_password(password)
            c.execute('INSERT INTO users (username, salt, pwd_hash) VALUES (?, ?, ?)', (username, salt_hex, hash_hex))
            conn.commit()
        return True, "Registered successfully. You can now log in."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    except Exception as e:
        return False, f"Registration failed: {e}"
def authenticate_user(username: str, password: str, db_path=DB_PATH):
    username = (username or '').strip()
    if not username or password is None:
        return False, "Username and password cannot be empty."
    try:
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute('SELECT salt, pwd_hash FROM users WHERE username = ?', (username,))
            row = c.fetchone()
    except Exception as e:
        return False, f"Authentication failed: {e}"
    if not row:
        return False, "User not found."
    salt_hex, hash_hex = row
    if verify_password(salt_hex, hash_hex, password):
        return True, "Login successful"
    else:
        return False, "Incorrect password."
def stdin_is_available():
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        return False
def run_cli_interactive(db_path=DB_PATH):
    create_db(db_path)
    while True:
        try:
            print("Choose: [1] Register  [2] Login  [3] Exit")
            choice = input('> ').strip()
        except (OSError, EOFError):
            break
        if choice == '1':
            try:
                username = input('Choose username: ').strip()
                password = getpass.getpass('Choose password: ')
                password_confirm = getpass.getpass('Confirm password: ')
            except (OSError, EOFError):
                continue
            if password != password_confirm:
                print('Passwords do not match.')
                continue
            ok, msg = register_user(username, password, db_path)
            print(msg)
        elif choice == '2':
            try:
                username = input('Username: ').strip()
                password = getpass.getpass('Password: ')
            except (OSError, EOFError):
                continue
            ok, msg = authenticate_user(username, password, db_path)
            print(msg)
            if ok:
                print(f'Welcome, {username}!')
        elif choice == '3' or choice.lower() in ('exit', 'quit'):
            break
        else:
            print('Invalid option.')
def run_cli_noninteractive(args, db_path=DB_PATH):
    create_db(db_path)
    if args.register:
        ok, msg = register_user(args.username, args.password, db_path)
        print(msg)
        return 0 if ok else 2
    if args.login:
        ok, msg = authenticate_user(args.username, args.password, db_path)
        print(msg)
        return 0 if ok else 3
    print('No action requested. Use --register or --login with --username and --password in non-interactive mode.')
    return 1
if TK_AVAILABLE:
    class LoginApp(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Secure Login — Python")
            self.geometry("680x420")
            self.resizable(False, False)
            self.configure(bg="#f0f2f5")
            self.style = ttk.Style(self)

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
            try:
                self.style.theme_use('clam')
            except Exception:
                pass
            self.style.configure('Card.TFrame', background='white', relief='flat')
            self.style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'), background='white')
            self.style.configure('TLabel', background='white')
            self.style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=6)
            self.left_frame = ttk.Frame(self, style='Card.TFrame')
            self.left_frame.place(x=30, y=40, width=300, height=340)
            self.right_frame = ttk.Frame(self, style='Card.TFrame')
            self.right_frame.place(x=350, y=40, width=300, height=340)
            ttk.Label(self.left_frame, text="Welcome Back!", style='Title.TLabel').pack(pady=(24,6))
            ttk.Label(self.left_frame, text="Login to your account", font=('Segoe UI', 10), background='white').pack(pady=(0,16))
            self.login_frame = ttk.Frame(self.right_frame, style='Card.TFrame')
            self.register_frame = ttk.Frame(self.right_frame, style='Card.TFrame')
            self.create_login_ui()
            self.create_register_ui()
            self.show_login()
            ttk.Label(self, text='Built with  •  Secure PBKDF2 password hashing', background='#f0f2f5', font=('Segoe UI', 8)).place(x=10, y=390)
        def create_login_ui(self):
            frame = self.login_frame
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            ttk.Label(frame, text='Username:').pack(anchor='w', padx=18, pady=(18,4))
            self.login_username = ttk.Entry(frame)
            self.login_username.pack(fill='x', padx=18)
            ttk.Label(frame, text='Password:').pack(anchor='w', padx=18, pady=(12,4))
            pass_frame = ttk.Frame(frame)
            pass_frame.pack(fill='x', padx=18)
            self.login_password = ttk.Entry(pass_frame, show='*')
            self.login_password.pack(side='left', fill='x', expand=True)
            self.show_pwd_var = tk.BooleanVar(value=False)
            self.show_pwd_btn = ttk.Checkbutton(pass_frame, text='Show', variable=self.show_pwd_var, command=self.toggle_password)
            self.show_pwd_btn.pack(side='left', padx=(8,0))
            self.remember_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(frame, text='Remember me', variable=self.remember_var).pack(anchor='w', padx=18, pady=(10,0))
            ttk.Button(frame, text='Login', command=self.handle_login).pack(fill='x', padx=18, pady=(12,6))
            ttk.Button(frame, text='Create account', command=self.show_register).pack(fill='x', padx=18)
        def create_register_ui(self):
            frame = self.register_frame
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            ttk.Label(frame, text='Choose a username:').pack(anchor='w', padx=18, pady=(18,4))
            self.reg_username = ttk.Entry(frame)
            self.reg_username.pack(fill='x', padx=18)
            ttk.Label(frame, text='Choose a password:').pack(anchor='w', padx=18, pady=(12,4))
            self.reg_password = ttk.Entry(frame, show='*')
            self.reg_password.pack(fill='x', padx=18)
            ttk.Label(frame, text='Confirm password:').pack(anchor='w', padx=18, pady=(12,4))
            self.reg_password_confirm = ttk.Entry(frame, show='*')
            self.reg_password_confirm.pack(fill='x', padx=18)
            self.pw_strength_label = ttk.Label(frame, text='')
            self.pw_strength_label.pack(anchor='w', padx=18, pady=(8,0))
            self.reg_password.bind('<KeyRelease>', self.update_strength)
            ttk.Button(frame, text='Register', command=self.handle_register).pack(fill='x', padx=18, pady=(12,6))
            ttk.Button(frame, text='Back to login', command=self.show_login).pack(fill='x', padx=18)
        def toggle_password(self):
            if self.show_pwd_var.get():
                self.login_password.config(show='')
            else:
                self.login_password.config(show='*')
        def show_register(self):
            self.login_frame.place_forget()
            self.register_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        def show_login(self):
            self.register_frame.place_forget()
            self.login_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        def handle_register(self):
            username = self.reg_username.get()
            pw = self.reg_password.get()
            pwc = self.reg_password_confirm.get()
            if pw != pwc:
                messagebox.showerror('Error', 'Passwords do not match.')
                return
            ok, msg = register_user(username, pw)
            if ok:
                messagebox.showinfo('Success', msg)
                self.reg_username.delete(0, 'end')
                self.reg_password.delete(0, 'end')
                self.reg_password_confirm.delete(0, 'end')
                self.pw_strength_label.config(text='')
                self.show_login()
            else:
                messagebox.showerror('Error', msg)
        def handle_login(self):
            username = self.login_username.get()
            pw = self.login_password.get()
            ok, msg = authenticate_user(username, pw)
            if ok:
                self.open_dashboard(username)
            else:
                messagebox.showerror('Login failed', msg)
        def update_strength(self, event=None):
            pw = self.reg_password.get()
            score = 0
            if len(pw) >= 8:
                score += 1
            if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
                score += 1
            if any(c.isdigit() for c in pw):
                score += 1
            if any(c in '!@#$%^&*()-_=+[]{};:,.<>?/' for c in pw):
                score += 1
            labels = {0: 'Very weak', 1: 'Weak', 2: 'Medium', 3: 'Strong', 4: 'Very strong'}
            self.pw_strength_label.config(text=f'Password strength: {labels[score]}')
        def open_dashboard(self, username: str):
            dash = tk.Toplevel(self)
            dash.title('Dashboard')
            dash.geometry('420x260')
            dash.resizable(False, False)
            ttk.Label(dash, text=f'Welcome, {username}!', font=('Segoe UI', 14, 'bold')).pack(pady=(24,8))
            ttk.Label(dash, text='You are now logged in. This is a sample dashboard.').pack(pady=(4,12))
            ttk.Button(dash, text='Logout', command=dash.destroy).pack(pady=(8,0))
            def run_tests():
test_db = 'test_users.db'
if os.path.exists(test_db):
os.remove(test_db)
create_db(test_db)
ok, msg = register_user('alice', 'Password123!', test_db)
assert ok, 'Failed to register alice: ' + msg
ok, msg = register_user('bob', 'S3cureP@ss', test_db)
assert ok, 'Failed to register bob: ' + msg
ok, msg = register_user('alice', 'another', test_db)
assert not ok and 'exists' in msg.lower(), 'Duplicate username not detected'
ok, msg = authenticate_user('alice', 'Password123!', test_db)
assert ok, 'Alice should authenticate'
ok, msg = authenticate_user('alice', 'wrong', test_db)
assert not ok and 'incorrect' in msg.lower(), 'Wrong password not detected'
ok, msg = authenticate_user('charlie', 'x', test_db)
assert not ok and 'not found' in msg.lower(), 'Non-existent user not handled'
ok, msg = register_user('', 'x', test_db)
assert not ok and 'cannot be empty' in msg.lower(), 'Empty username allowed'
ok, msg = register_user('δユーザ', 'ユニコードP@ss', test_db)
assert ok, 'Unicode username registration failed'
ok, msg = register_user('samepass1', 'common', test_db)
assert ok
ok, msg = register_user('samepass2', 'common', test_db)
assert ok
with sqlite3.connect(test_db) as conn:
c = conn.cursor()
c.execute('SELECT salt FROM users WHERE username = ?', ('samepass1',))
s1 = c.fetchone()[0]
c.execute('SELECT salt FROM users WHERE username = ?', ('samepass2',))
s2 = c.fetchone()[0]
assert s1 != s2, 'Different users with same password should have different salts'
if os.path.exists(test_db):
os.remove(test_db)
def main(argv):
parser = argparse.ArgumentParser()
parser.add_argument('--test', action='store_true')
parser.add_argument('--cli', action='store_true')
parser.add_argument('--register', action='store_true')
parser.add_argument('--login', action='store_true')
parser.add_argument('--username', type=str, default='')
parser.add_argument('--password', type=str, default='')
args = parser.parse_args(argv)
if args.test:
run_tests()
print('All tests passed.')
return
create_db()
if args.register or args.login:
if not args.username or not args.password:
print('When using --register or --login in non-interactive mode, you must provide --username and --password')
return
rc = run_cli_noninteractive(args)
sys.exit(rc)
if not stdin_is_available():
if not TK_AVAILABLE:
print('No stdin available and tkinter is not installed in this environment.')
print('Options:')
print(' - Run tests: python tk_login_app.py --test')
print(' - Use non-interactive flags to register/login:')
print(' python tk_login_app.py --register --username alice --password "P@ss"')
print(' - Run in an environment with stdin or install tkinter for GUI.')
return


# journal_app.py
import os
import uuid
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import scrolledtext
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

def generate_key(password: str, salt: bytes = None) -> bytes:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_entry(entry: str, password: str) -> tuple[bytes, bytes]:
    key, salt = generate_key(password)
    f = Fernet(key)
    encrypted_entry = f.encrypt(entry.encode())
    return encrypted_entry, salt

def decrypt_entry(encrypted_entry: bytes, password: str, salt: bytes) -> str:
    key, _ = generate_key(password, salt)
    f = Fernet(key)
    decrypted_entry = f.decrypt(encrypted_entry).decode()
    return decrypted_entry

def save_entry(entry: str, password: str) -> str:
    encrypted_entry, salt = encrypt_entry(entry, password)
    now = datetime.datetime.now()
    year = now.year
    filename = f"{now.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4()}.dat"
    folder = os.path.join("entries", str(year))
    os.makedirs(folder, exist_ok=True)
    filepath = os.path.join(folder, filename)

    with open(filepath, "wb") as f:
        f.write(salt + b"|||" + encrypted_entry)
    return filepath

def load_entry(filepath: str, password: str) -> str:
    with open(filepath, "rb") as f:
        data = f.read()
        salt, encrypted_entry = data.split(b"|||", 1)
    return decrypt_entry(encrypted_entry, password, salt)

def get_access_date(filepath:str):
    filename = os.path.basename(filepath)
    date_str = filename.split('-')[0]
    entry_datetime = datetime.datetime.strptime(date_str, '%Y%m%d')
    access_datetime = entry_datetime + datetime.timedelta(days=365)
    return access_datetime

class JournalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Minimalist Journal")

        # DPI Scaling and Window Size
        self.root.tk.call('tk', 'scaling', 2.0)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = int(screen_width * 0.6)
        window_height = int(screen_height * 0.6)
        self.root.geometry(f"{window_width}x{window_height}")

        self.style = ttk.Style(theme="darkly")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("monospace", 12))
        self.text_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        self.text_area.configure(background='#383838', foreground='white', insertbackground='white')

        self.password_label = ttk.Label(root, text="Password:", style="TLabel")
        self.password_label.pack()
        self.password_entry = ttk.Entry(root, show="*", style="TEntry")
        self.password_entry.pack()

        self.save_button = ttk.Button(root, text="Save Entry", command=self.save_journal_entry, style="success.TButton")
        self.save_button.pack(pady=10)

        self.menu_button = ttk.Button(root, text="More", command=self.show_menu, style="TButton")
        self.menu_button.pack(side=tk.LEFT, anchor=tk.SW, padx=10, pady=10)

        self.theme_var = tk.BooleanVar()
        self.theme_var.set(True)
        self.theme_toggle = ttk.Checkbutton(root, text="Dark Theme", variable=self.theme_var, command=self.toggle_theme, style="TCheckbutton")
        self.theme_toggle.pack()

    def save_journal_entry(self):
        entry = self.text_area.get("1.0", tk.END).strip()
        password = self.password_entry.get()

        if not entry:
            messagebox.showerror("Error", "Entry cannot be empty.")
            return

        if len(entry) > 10000:
            messagebox.showerror("Error", "Entry exceeds 10,000 character limit.")
            return

        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        if messagebox.askyesno("Confirm", "Are you sure you want to save this entry?"):
            filepath = save_entry(entry, password)
            messagebox.showinfo("Success", f"Entry saved successfully. It will be accessible on {get_access_date(filepath).strftime('%Y-%m-%d %H:%M:%S')}")
            self.text_area.delete("1.0", tk.END)
            self.password_entry.delete(0, tk.END)

    def toggle_theme(self):
        if self.theme_var.get():
            self.style.configure('.', background='#282828', foreground='white')
            self.style.configure('TEntry', fieldbackground='#383838', foreground='white')
            self.text_area.configure(background='#383838', foreground='white', insertbackground='white')
            self.style.configure('success.TButton', background='#4CAF50', foreground='white')
            self.style.configure('TCheckbutton', background='#282828', foreground='white')
        else:
            self.style.configure('.', background='white', foreground='black')
            self.style.configure('TEntry', fieldbackground='lightgray', foreground='black')
            self.text_area.configure(background='lightgray', foreground='black', insertbackground='black')
            self.style.configure('success.TButton', background='#4CAF50', foreground='black')
            self.style.configure('TCheckbutton', background='white', foreground='black')

    def show_menu(self):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="View Unlocked Entries", command=self.view_unlocked_entries)
        menu.add_command(label="Current Locked Entries", command=self.show_locked_count)
        menu.add_command(label="Clear All Locked Entries", command=self.clear_locked_entries)
        menu.post(self.menu_button.winfo_rootx(), self.menu_button.winfo_rooty() + self.menu_button.winfo_height())

    def view_unlocked_entries(self):
        entries = self.get_unlocked_entries()
        if not entries:
            messagebox.showinfo("Info", "No unlocked entries found.")
            return

        unlocked_text = ""
        for filepath, access_date in entries:
            password = simpledialog.askstring("Password", f"Enter password for entry from {access_date.strftime('%Y-%m-%d %H:%M:%S')}:", show='*')
            if password:
                try:
                    entry = load_entry(filepath, password)
                    unlocked_text += f"\n\nEntry from {access_date.strftime('%Y-%m-%d %H:%M:%S')}:\n{entry}"
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {e}")
            else:
                return

        if unlocked_text:
            text_window = tk.Toplevel(self.root)
            text_window.title("Unlocked Entries")
            text_area = scrolledtext.ScrolledText(text_window, wrap=tk.WORD, font=("monospace", 12))
            text_area.insert(tk.END, unlocked_text)
            text_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    def get_unlocked_entries(self):
        unlocked_entries = []
        for year in os.listdir("entries"):
            year_path = os.path.join("entries", year)
            if os.path.isdir(year_path):
                for filename in os.listdir(year_path):
                    filepath = os.path.join(year_path, filename)
                    access_date = get_access_date(filepath)
                    if datetime.datetime.now() >= access_date:
                        unlocked_entries.append((filepath, access_date))
        return unlocked_entries

    def show_locked_count(self):
        count = self.get_locked_count()
        messagebox.showinfo("Locked Entries", f"Number of locked entries: {count}")

    def get_locked_count(self):
        count = 0
        for year in os.listdir("entries"):
            year_path = os.path.join("entries", year)
            if os.path.isdir(year_path):
                count += len(os.listdir(year_path))
        return count

    def clear_locked_entries(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all locked entries? This action cannot be undone."):
            try:
                for year in os.listdir("entries"):
                    year_path = os.path.join("entries", year)
                    if os.path.isdir(year_path):
                        for filename in os.listdir(year_path):
                            filepath = os.path.join(year_path, filename)
                            os.remove(filepath)
                        os.rmdir(year_path)
                messagebox.showinfo("Success", "All locked entries cleared.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear entries: {e}")

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = JournalApp(root)
    root.mainloop()
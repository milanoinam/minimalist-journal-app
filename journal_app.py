# journal_app.py
import os
import uuid
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext

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
        self.root.geometry("600x400")
        self.root.configure(bg="#282828") #dark theme default.

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("monospace", 12), bg="#383838", fg="white", insertbackground="white")
        self.text_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.password_label = tk.Label(root, text="Password:", bg="#282828", fg="white")
        self.password_label.pack()
        self.password_entry = tk.Entry(root, show="*", bg="#383838", fg="white")
        self.password_entry.pack()

        self.save_button = tk.Button(root, text="Save Entry", command=self.save_journal_entry, bg="#4CAF50", fg="white")
        self.save_button.pack(pady=10)

        self.theme_var = tk.BooleanVar()
        self.theme_var.set(True)  # Dark theme default
        self.theme_toggle = tk.Checkbutton(root, text="Dark Theme", variable=self.theme_var, command=self.toggle_theme, bg="#282828", fg="white", selectcolor="#282828")
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
        if self.theme_var.get():  # Dark theme
            self.root.configure(bg="#282828")
            self.text_area.configure(bg="#383838", fg="white", insertbackground="white")
            self.save_button.configure(bg="#4CAF50", fg="white")
            self.password_label.configure(bg="#282828", fg="white")
            self.password_entry.configure(bg="#383838", fg="white")
            self.theme_toggle.configure(bg="#282828", fg="white", selectcolor="#282828")
        else:  # Light theme
            self.root.configure(bg="white")
            self.text_area.configure(bg="lightgray", fg="black", insertbackground="black")
            self.save_button.configure(bg="#4CAF50", fg="black")
            self.password_label.configure(bg="white", fg="black")
            self.password_entry.configure(bg="lightgray", fg="black")
            self.theme_toggle.configure(bg="white", fg="black", selectcolor="white")

if __name__ == "__main__":
    root = tk.Tk()
    app = JournalApp(root)
    root.mainloop()
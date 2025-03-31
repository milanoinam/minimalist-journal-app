import os
import json
import datetime
import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import scrolledtext
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import time  # Import time for lockout functionality

PASSWORD_FILE = "password.dat"
ENTRIES_FILE = "entries.json"

# Global variable to store the password
user_password = None


def save_password(password: str):
    """
    Save the password to a file.
    """
    with open(PASSWORD_FILE, "w") as f:
        f.write(password)


def load_password() -> str:
    """
    Load the password from the file.
    """
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as f:
            return f.read().strip()
    return None


def load_entries() -> dict:
    """
    Load all entries from the JSON file.
    """
    if os.path.exists(ENTRIES_FILE):
        with open(ENTRIES_FILE, "r") as f:
            return json.load(f)
    return {}


def save_entries(entries: dict):
    """
    Save all entries to the JSON file.
    """
    with open(ENTRIES_FILE, "w") as f:
        json.dump(entries, f, indent=4)


class JournalApp:
    def __init__(self, root):
        global user_password
        self.failed_attempts = 0  # Track failed attempts
        self.lockout_time = None  # Track lockout time

        self.root = root
        self.root.title("Minimalist Journal")

        # Center and resize the main app window
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = int(screen_width * 0.66)  # 66% of screen width
        window_height = int(screen_height * 0.66)  # 66% of screen height
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # Load the stored password
        user_password = load_password()

        # Configure the UI
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("monospace", 16))
        self.text_area.pack(pady=15, padx=15, fill=tk.BOTH, expand=True)

        self.placeholder = "Type your entry here..."
        self.text_area.insert("1.0", self.placeholder)
        self.text_area.tag_configure("placeholder", foreground="gray", font=("monospace", 16, "italic"))
        self.text_area.tag_add("placeholder", "1.0", "end")

        self.text_area.bind("<FocusIn>", self.clear_placeholder)
        self.text_area.bind("<FocusOut>", self.add_placeholder)

        self.save_button = ttk.Button(root, text="Save Entry", command=self.save_journal_entry, style="success.TButton")
        self.save_button.pack(pady=15)

        self.menu_button = ttk.Button(root, text="More", command=self.show_menu, style="TButton")
        self.menu_button.pack(side=tk.LEFT, anchor=tk.SW, padx=15, pady=15)

    def clear_placeholder(self, event):
        if self.text_area.get("1.0", "end-1c") == self.placeholder:
            self.text_area.delete("1.0", "end")
            self.text_area.tag_remove("placeholder", "1.0", "end")

    def add_placeholder(self, event):
        if not self.text_area.get("1.0", "end-1c"):
            self.text_area.insert("1.0", self.placeholder)
            self.text_area.tag_add("placeholder", "1.0", "end")

    def save_journal_entry(self):
        global user_password

        # Check if the password is set
        if not user_password:
            messagebox.showerror("Error", "No password set. Please set a password first.")
            return

        # Get the entry and strip whitespace
        entry = self.text_area.get("1.0", tk.END).strip()

        # Validate the entry
        if not entry or entry == self.placeholder:
            messagebox.showerror("Error", "Entry cannot be empty or contain only whitespace.")
            return

        # Load existing entries
        entries = load_entries()

        # Add the new entry with a timestamp
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        entries[timestamp] = entry

        # Save all entries back to the file
        save_entries(entries)

        messagebox.showinfo("Success", "Entry saved successfully.")
        self.text_area.delete("1.0", tk.END)
        self.add_placeholder(None)

    def show_menu(self):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Set/Change Password", command=self.set_password)
        menu.add_command(label="View Unlocked Entries", command=self.view_unlocked_entries)
        menu.add_command(label="Clear All Entries", command=self.clear_all_entries)
        menu.post(self.menu_button.winfo_rootx(), self.menu_button.winfo_rooty() + self.menu_button.winfo_height())

    def set_password(self):
        global user_password

        # Create a custom password dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Set/Change Password")
        dialog.geometry("400x250")
        dialog.transient(self.root)
        dialog.grab_set()

        # Add labels and entry fields
        tk.Label(dialog, text="Enter current password:", font=("TkDefaultFont", 14)).pack(pady=10)
        current_password_entry = ttk.Entry(dialog, show="*", font=("TkDefaultFont", 14))
        current_password_entry.pack(pady=5, padx=20, fill=tk.X)

        error_label = tk.Label(dialog, text="", font=("TkDefaultFont", 12), foreground="red")
        error_label.pack(pady=5)

        def submit_password():
            global user_password  # Declare user_password as global
            nonlocal error_label
            current_password = current_password_entry.get()

            # Check if the user is locked out
            if self.lockout_time and time.time() < self.lockout_time:
                error_label.config(text="You have tried 3 times. Try again after 5 minutes.")
                return

            # Verify the current password
            if user_password and current_password != user_password:
                self.failed_attempts += 1
                if self.failed_attempts >= 3:
                    self.lockout_time = time.time() + 300  # Lock out for 5 minutes
                    error_label.config(text="You have tried 3 times. Try again after 5 minutes.")
                else:
                    error_label.config(text="Incorrect current password.")
                return

            # Reset failed attempts and lockout time
            self.failed_attempts = 0
            self.lockout_time = None

            # Prompt for the new password
            new_password = simpledialog.askstring("Password", "Enter new password:", show='*')
            if not new_password:
                error_label.config(text="Password cannot be empty.")
                return

            # Save the new password
            save_password(new_password)
            user_password = new_password
            messagebox.showinfo("Success", "Password updated successfully.")
            dialog.destroy()

        submit_button = ttk.Button(dialog, text="Submit", command=submit_password, style="primary.TButton")
        submit_button.pack(pady=10)

    def view_unlocked_entries(self):
        global user_password

        # Check if the password is set
        if not user_password:
            messagebox.showerror("Error", "No password set. Please set a password first.")
            return

        # Create a custom password dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Password")
        dialog.geometry("400x250")  # Set a larger size for better visibility
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog on the screen
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        # Add labels and entry fields
        tk.Label(dialog, text="Enter password to view entries:", font=("TkDefaultFont", 14)).pack(pady=10)
        password_entry = ttk.Entry(dialog, show="*", font=("TkDefaultFont", 14))
        password_entry.pack(pady=5, padx=20, fill=tk.X)

        error_label = tk.Label(dialog, text="", font=("TkDefaultFont", 12), foreground="red")
        error_label.pack(pady=5)

        def submit_password():
            nonlocal error_label
            entered_password = password_entry.get()

            # Check if the user is locked out
            if self.lockout_time and time.time() < self.lockout_time:
                error_label.config(text="You have tried 3 times. Try again after 5 minutes.")
                return

            # Verify the entered password
            if entered_password != user_password:
                self.failed_attempts += 1
                if self.failed_attempts >= 3:
                    self.lockout_time = time.time() + 300  # Lock out for 5 minutes
                    error_label.config(text="You have tried 3 times. Try again after 5 minutes.")
                else:
                    error_label.config(text="Incorrect password. Please try again.")
                return

            # Reset failed attempts and lockout time
            self.failed_attempts = 0
            self.lockout_time = None

            # Load and display entries
            entries = load_entries()
            if not entries:
                messagebox.showinfo("Info", "No entries found.")
                dialog.destroy()
                return

            unlocked_text = ""
            for timestamp, entry in entries.items():
                unlocked_text += f"\n\nEntry from {timestamp}:\n{entry}"

            # Display the entries in a new window
            text_window = tk.Toplevel(self.root)
            text_window.title("Unlocked Entries")
            text_area = scrolledtext.ScrolledText(text_window, wrap=tk.WORD, font=("monospace", 12))
            text_area.insert(tk.END, unlocked_text)
            text_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

            dialog.destroy()

        submit_button = ttk.Button(dialog, text="Submit", command=submit_password, style="primary.TButton")
        submit_button.pack(pady=10)

    def clear_all_entries(self):
        global user_password

        # Check if the password is set
        if not user_password:
            messagebox.showerror("Error", "No password set. Please set a password first.")
            return

        # Prompt for the password
        entered_password = simpledialog.askstring("Password", "Enter password to clear entries:", show='*')
        if entered_password != user_password:
            messagebox.showerror("Error", "Incorrect password.")
            return

        # Confirm and clear all entries
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all entries? This action cannot be undone."):
            if os.path.exists(ENTRIES_FILE):
                os.remove(ENTRIES_FILE)
            messagebox.showinfo("Success", "All entries cleared.")


if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = JournalApp(root)
    root.mainloop()
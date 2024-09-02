import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from functools import partial
from triple_des import process_ecrypt, process_decrypt

class ThreeDESEncryptDecryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("3DES Encrypt/Decrypt")
        
        self.file_path = ""
        self.keys_path = ""
        self.operation = tk.StringVar()
        self.operation.set("encrypt")

        # File Selection Frame
        file_frame = ttk.LabelFrame(root, text="File")
        file_frame.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        ttk.Label(file_frame, text="Plaintext/Ciphertext File:").grid(row=0, column=0, sticky="w")
        self.file_entry = ttk.Entry(file_frame, width=40)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5, pady=5)

        # Operation Selection Frame
        operation_frame = ttk.LabelFrame(root, text="Operation")
        operation_frame.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        ttk.Radiobutton(operation_frame, text="Encrypt", variable=self.operation, value="encrypt").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Radiobutton(operation_frame, text="Decrypt", variable=self.operation, value="decrypt").grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # Keys Selection Frame
        self.keys_frame = ttk.LabelFrame(root, text="Keys")
        self.keys_frame.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.keys_frame.grid_remove()

        ttk.Label(self.keys_frame, text="Keys File:").grid(row=0, column=0, sticky="w")
        self.keys_entry = ttk.Entry(self.keys_frame, width=40)
        self.keys_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Button(self.keys_frame, text="Browse", command=self.browse_keys_file).grid(row=0, column=2, padx=5, pady=5)

        # Button Frame
        button_frame = ttk.Frame(root)
        button_frame.grid(row=3, column=0, padx=10, pady=5, sticky="w")

        ttk.Button(button_frame, text="Run", command=self.run_operation).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(button_frame, text="Exit", command=self.root.quit).grid(row=0, column=1, padx=5, pady=5)

        # Binding operation change to show/hide keys frame
        self.operation.trace_add("write", self.show_hide_keys_frame)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, self.file_path)

    def browse_keys_file(self):
        self.keys_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.keys_entry.delete(0, tk.END)
        self.keys_entry.insert(0, self.keys_path)

    def show_hide_keys_frame(self, *args):
        if self.operation.get() == "decrypt":
            self.keys_frame.grid()
        else:
            self.keys_frame.grid_remove()

    def run_operation(self):
        file_path = self.file_entry.get()
        keys_path = self.keys_entry.get()

        if not file_path:
            messagebox.showerror("Error", "Please select a file.")
            return

        if self.operation.get() == "decrypt" and not keys_path:
            messagebox.showerror("Error", "Please select a keys file for decryption.")
            return

        if self.operation.get() == "encrypt":
            try:
                # Perform encryption
                encrypted_text = process_ecrypt(file_path, "0000111122223333")  # Assuming fixed IV for demonstration
                messagebox.showinfo("Encryption Successful", "Encryption completed. Check cyphertext.txt")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            try:
                # Perform decryption with keys file
                decrypted_text = process_decrypt(file_path, "0000111122223333", keys_path)  # Assuming fixed IV for demonstration
                messagebox.showinfo("Decryption Successful", "Decryption completed. Check decyphered_text.txt")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = ThreeDESEncryptDecryptApp(root)
    root.mainloop()

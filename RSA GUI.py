import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import random

# === RSA Functions ===

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = modinv(e, phi)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    key, n = pk
    return [pow(ord(char), key, n) for char in plaintext]

def decrypt(pk, ciphertext):
    key, n = pk
    return ''.join([chr(pow(char, key, n)) for char in ciphertext])

# === GUI Setup ===

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption Tool-CB012655")
        self.public_key = None
        self.private_key = None

        self.build_gui()

    def build_gui(self):
        self.mode_var = tk.StringVar(value="key")
        tk.Label(self.root, text="Choose Mode:").pack()
        tk.Radiobutton(self.root, text="Generate Keypair + Text", variable=self.mode_var, value="key", command=self.show_text_ui).pack()
        tk.Radiobutton(self.root, text="Encrypt/Decrypt File", variable=self.mode_var, value="file", command=self.show_file_ui).pack()

        self.content_frame = tk.Frame(self.root)
        self.content_frame.pack(fill='both', expand=True)
        self.show_text_ui()

    def clear_content_frame(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_text_ui(self):
        self.clear_content_frame()
        tk.Label(self.content_frame, text="Enter Prime p (100–200):").pack()
        self.p_entry = tk.Entry(self.content_frame)
        self.p_entry.pack()

        tk.Label(self.content_frame, text="Enter Prime q (100–200):").pack()
        self.q_entry = tk.Entry(self.content_frame)
        self.q_entry.pack()

        tk.Button(self.content_frame, text="Generate Keys", command=self.generate_keys).pack()

        self.keys_display = tk.Label(self.content_frame, text="")
        self.keys_display.pack()

        tk.Label(self.content_frame, text="Enter message to encrypt:").pack()
        self.message_entry = tk.Entry(self.content_frame, width=50)
        self.message_entry.pack()

        tk.Button(self.content_frame, text="Encrypt + Decrypt", command=self.process_text_encryption).pack()
        self.result_box = scrolledtext.ScrolledText(self.content_frame, width=50, height=10)
        self.result_box.pack()

    def show_file_ui(self):
        self.clear_content_frame()
        tk.Button(self.content_frame, text="Select File to Encrypt", command=self.encrypt_file).pack(pady=10)
        tk.Button(self.content_frame, text="Select File to Decrypt", command=self.decrypt_file).pack(pady=10)

    def generate_keys(self):
        try:
            p = int(self.p_entry.get())
            q = int(self.q_entry.get())
            if not (100 <= p <= 200 and 100 <= q <= 200):
                raise ValueError("Primes must be in range.")
            if not (is_prime(p) and is_prime(q)) or p == q:
                raise ValueError("Both must be different primes.")
            self.public_key, self.private_key = generate_keypair(p, q)
            self.keys_display.config(text=f"Public: {self.public_key}\nPrivate: {self.private_key}")
        except Exception as e:
            messagebox.showerror("Invalid Input", str(e))

    def process_text_encryption(self):
        msg = self.message_entry.get()
        if not self.public_key or not self.private_key:
            messagebox.showerror("Key Error", "Please generate keys first.")
            return
        enc = encrypt(self.public_key, msg)
        dec = decrypt(self.private_key, enc)
        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, f"Encrypted:\n{enc}\n\nDecrypted:\n{dec}")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        with open(file_path, 'r', encoding='utf-8') as f:
            data = f.read()
        p, q = 137, 149  # You can randomize or prompt for secure use
        pub, priv = generate_keypair(p, q)
        encrypted = encrypt(pub, data)
        out_file = os.path.join(os.path.dirname(file_path), "encrypted_output.txt")
        with open(out_file, 'w') as f:
            f.write(','.join(map(str, encrypted)))
        messagebox.showinfo("Success", f"Encrypted file saved as {out_file}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            with open(file_path, 'r') as f:
                encrypted_data = list(map(int, f.read().split(',')))
            p, q = 137, 149
            pub, priv = generate_keypair(p, q)
            decrypted = decrypt(priv, encrypted_data)
            out_file = os.path.join(os.path.dirname(file_path), "decrypted_output.txt")
            with open(out_file, 'w', encoding='utf-8') as f:
                f.write(decrypted)
            messagebox.showinfo("Success", f"Decrypted file saved as {out_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt: {e}")

# === Main App Runner ===
if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()

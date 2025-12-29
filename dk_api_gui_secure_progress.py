import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import json
import os
import csv
import time
import threading
import requests
import base64
from datetime import datetime
from cryptography.fernet import Fernet

# ================== CONSTANTS ==================
TOKEN_URL = "https://api.digikey.com/v1/oauth2/token"
KEYWORD_SEARCH_URL = "https://api.digikey.com/products/v4/search/keyword"

APP_DIR = os.path.join(os.path.expanduser("~"), ".dk_api_gui")
CONFIG_FILE = os.path.join(APP_DIR, "config.enc")
KEY_FILE = os.path.join(APP_DIR, "key.key")

REQUEST_TIMEOUT = 30
TOKEN_MARGIN = 30
DELAY_BETWEEN_CALLS = 0.25
# ==============================================


# ---------------- Encryption ----------------
def load_cipher():
    os.makedirs(APP_DIR, exist_ok=True)
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)


# ---------------- Token Manager ----------------
class DigiKeyTokenManager:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.expiry = 0

    def get_token(self):
        if self.token and time.time() < self.expiry:
            return self.token

        pair = f"{self.client_id}:{self.client_secret}"
        encoded = base64.b64encode(pair.encode()).decode()

        headers = {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        r = requests.post(
            TOKEN_URL,
            headers=headers,
            data={"grant_type": "client_credentials"},
            timeout=REQUEST_TIMEOUT
        )
        r.raise_for_status()

        data = r.json()
        self.token = data["access_token"]
        self.expiry = time.time() + data["expires_in"] - TOKEN_MARGIN
        return self.token


# ---------------- Digi-Key API ----------------
def fetch_part(input_pn, token, client_id):
    headers = {
        "Authorization": f"Bearer {token}",
        "X-DIGIKEY-Client-Id": client_id,
        "X-DIGIKEY-Locale-Site": "US",
        "X-DIGIKEY-Locale-Language": "en",
        "X-DIGIKEY-Locale-Currency": "USD",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "Keywords": input_pn,
        "RecordCount": 1
    }

    r = requests.post(
        KEYWORD_SEARCH_URL,
        headers=headers,
        json=payload,
        timeout=REQUEST_TIMEOUT
    )

    if r.status_code != 200:
        return "", "", f"API_ERROR_{r.status_code}"

    products = r.json().get("Products", [])
    if not products:
        return "", "", "NO_RESULTS"

    p = products[0]
    mfr = p.get("Manufacturer", {}).get("Name", "")
    mpn = p.get("ManufacturerProductNumber", "")

    if not mpn:
        variations = p.get("ProductVariations", [])
        if variations:
            mpn = variations[0].get("ManufacturerProductNumber", "")

    return mfr, mpn, "OK"


# ---------------- GUI ----------------
class DigiKeyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Digi-Key API Lookup Tool")
        self.root.geometry("760x560")
        self.root.resizable(False, False)

        self.client_id = tk.StringVar()
        self.client_secret = tk.StringVar()
        self.remember = tk.BooleanVar()
        self.input_csv = tk.StringVar()

        self.cipher = load_cipher()
        self.load_config()
        self.build_ui()

    def build_ui(self):
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="Digi-Key API Lookup Tool", font=("Segoe UI", 14, "bold")).pack(anchor="w")

        creds = ttk.LabelFrame(main, text="API Credentials", padding=10)
        creds.pack(fill="x", pady=10)

        ttk.Label(creds, text="Client ID").grid(row=0, column=0, sticky="w")
        ttk.Entry(creds, textvariable=self.client_id, width=60).grid(row=0, column=1)

        ttk.Label(creds, text="Client Secret").grid(row=1, column=0, sticky="w")
        ttk.Entry(creds, textvariable=self.client_secret, show="*", width=60).grid(row=1, column=1)

        ttk.Checkbutton(
            creds,
            text="Remember credentials (encrypted)",
            variable=self.remember
        ).grid(row=2, column=1, sticky="w", pady=(6, 0))

        files = ttk.LabelFrame(main, text="Input", padding=10)
        files.pack(fill="x")

        ttk.Button(files, text="Select Input CSV", command=self.pick_input).grid(row=0, column=0)
        ttk.Entry(files, textvariable=self.input_csv, width=60).grid(row=0, column=1, padx=6)

        self.run_btn = ttk.Button(main, text="Run Lookup", command=self.run)
        self.run_btn.pack(pady=10)

        self.progress = ttk.Progressbar(main, length=700, mode="determinate")
        self.progress.pack(pady=4)

        self.log = scrolledtext.ScrolledText(main, height=14, font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)

    def log_msg(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def pick_input(self):
        path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if path:
            self.input_csv.set(path)

    def save_config(self):
        if not self.remember.get():
            return
        data = json.dumps({
            "client_id": self.client_id.get(),
            "client_secret": self.client_secret.get()
        }).encode()
        enc = self.cipher.encrypt(data)
        with open(CONFIG_FILE, "wb") as f:
            f.write(enc)

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "rb") as f:
                data = self.cipher.decrypt(f.read())
                creds = json.loads(data.decode())
                self.client_id.set(creds.get("client_id", ""))
                self.client_secret.set(creds.get("client_secret", ""))
                self.remember.set(True)

    # ---------- Thread-safe run ----------
    def run(self):
        if not all([self.client_id.get(), self.client_secret.get(), self.input_csv.get()]):
            messagebox.showerror("Missing data", "Client ID, Client Secret and Input CSV are required.")
            return

        self.run_btn.config(state="disabled")
        self.progress["value"] = 0
        self.log.delete("1.0", tk.END)

        threading.Thread(target=self.run_worker, daemon=True).start()

    def run_worker(self):
        try:
            self.save_config()

            input_path = self.input_csv.get()
            input_dir = os.path.dirname(input_path)
            output_path = os.path.join(
                input_dir,
                f"output_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
            )

            with open(input_path, newline="", encoding="utf-8-sig") as f:
                rows = list(csv.DictReader(f))

            total = len(rows)
            self.root.after(0, lambda: self.progress.config(maximum=total))

            token_mgr = DigiKeyTokenManager(
                self.client_id.get(),
                self.client_secret.get()
            )

            with open(output_path, "w", newline="", encoding="utf-8") as f_out:
                writer = csv.DictWriter(
                    f_out,
                    fieldnames=["Input_PN", "MFR", "MPN", "Status"]
                )
                writer.writeheader()

                for i, row in enumerate(rows, 1):
                    pn = row.get("Input_PN", "").strip()

                    self.root.after(0, lambda p=pn, i=i, t=total:
                        self.log_msg(f"[{i}/{t}] Looking up {p}")
                    )

                    try:
                        token = token_mgr.get_token()
                        mfr, mpn, status = fetch_part(pn, token, self.client_id.get())
                    except Exception:
                        mfr = mpn = ""
                        status = "EXCEPTION"

                    writer.writerow({
                        "Input_PN": pn,
                        "MFR": mfr,
                        "MPN": mpn,
                        "Status": status
                    })

                    self.root.after(0, lambda i=i:
                        self.progress.config(value=i)
                    )

                    time.sleep(DELAY_BETWEEN_CALLS)

            self.root.after(0, lambda: self.finish(output_path))

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.root.after(0, lambda: self.run_btn.config(state="normal"))

    def finish(self, output_path):
        self.run_btn.config(state="normal")
        self.log_msg(f"\nDone! Output saved to:\n{output_path}")
        messagebox.showinfo("Completed", f"Output file created:\n{output_path}")


# ---------------- Launch ----------------
if __name__ == "__main__":
    root = tk.Tk()
    DigiKeyGUI(root)
    root.mainloop()


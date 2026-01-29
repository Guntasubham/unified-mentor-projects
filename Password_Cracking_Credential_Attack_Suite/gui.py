import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from PIL import Image, ImageTk
import hashlib, itertools, string, math, threading, random, datetime

# ----------------- HELPER FUNCTIONS -----------------

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def identify_hash_algo(hash_str):
    """Identifies hash type based on prefix (Documentation Req: Scope B)"""
    if hash_str.startswith("$1$"): return "MD5"
    if hash_str.startswith("$2a$") or hash_str.startswith("$2y$"): return "Bcrypt"
    if hash_str.startswith("$5$"): return "SHA-256"
    if hash_str.startswith("$6$"): return "SHA-512"
    if len(hash_str) == 32: return "NTLM / MD5 (Raw)"
    return "Unknown/Generic"

def generate_dictionary(words):
    mutations = set()
    for w in words:
        mutations.update([
            w, w.lower(), w.upper(), w.capitalize(),
            w + "123", w + "2024",
            w.replace('a', '@').replace('o', '0')
        ])
    return list(mutations)

def dictionary_attack(target_hash, wordlist, progress_callback=None):
    total = len(wordlist)
    for i, word in enumerate(wordlist):
        if hash_password(word) == target_hash:
            return word
        if progress_callback:
            progress_callback((i + 1) / total * 100)
    return None

def brute_force_attack(target_hash, max_len=4):
    chars = string.ascii_lowercase + string.digits
    for length in range(1, max_len + 1):
        for combo in itertools.product(chars, repeat=length):
            attempt = ''.join(combo)
            if hash_password(attempt) == target_hash:
                return attempt
    return None

def password_strength(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password): charset += len(string.punctuation)
    entropy = len(password) * math.log2(charset) if charset else 0
    if entropy < 40: return entropy, "Weak"
    elif entropy < 60: return entropy, "Moderate"
    return entropy, "Strong"

# ----------------- MAIN APP -----------------

class PasswordAuditApp:
    def __init__(self, root):
        self.root = root
        self.audit_logs = []  # Store events for the report
        
        root.title("Password Cracking & Credential Attack Suite")
        root.geometry("1050x650")
        root.resizable(False, False)

        # Background Canvas
        self.canvas = tk.Canvas(root, width=1050, height=650, highlightthickness=0)
        self.canvas.place(x=0, y=0)

        try:
            bg_image = Image.open("background.jpg").resize((1050, 650))
            self.bg_photo = ImageTk.PhotoImage(bg_image)
            self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")
        except:
            self.canvas.config(bg="black") # Fallback if image missing

        # Animated Particles (Original Styling)
        self.particles = []
        for _ in range(80):
            x = random.randint(0, 1050)
            y = random.randint(0, 650)
            r = random.randint(1, 3)
            obj = self.canvas.create_oval(x, y, x+r, y+r, fill="#00ffff", outline="")
            dx = random.choice([-1, 1])
            dy = random.choice([-1, 1])
            self.particles.append([obj, dx, dy])

        self.animate_particles()

        # Intro Overlay (transparent style)
        self.intro_frame = tk.Frame(root, bg="#000000")
        self.intro_frame.place(x=0, y=0, width=1050, height=650)
        self.intro_frame.attributes = None
        self.build_intro()

    # ---------------- Animation ----------------
    def animate_particles(self):
        for p in self.particles:
            obj, dx, dy = p
            self.canvas.move(obj, dx, dy)
            x1, y1, x2, y2 = self.canvas.coords(obj)
            if x1 <= 0 or x2 >= 1050:
                p[1] *= -1
            if y1 <= 0 or y2 >= 650:
                p[2] *= -1
        self.root.after(30, self.animate_particles)

    # ---------------- Intro Page ----------------
    def build_intro(self):
        tk.Label(self.intro_frame, text="Password Cracking Suite",
                 font=("Segoe UI", 28, "bold"),
                 fg="cyan", bg="#000000").pack(pady=140)

        tk.Label(self.intro_frame, text="Cybersecurity Credential Attack Toolkit",
                 font=("Segoe UI", 14),
                 fg="white", bg="#000000").pack(pady=10)

        tk.Button(self.intro_frame, text="Lets Crack",
                  font=("Segoe UI", 16, "bold"),
                  bg="#d9534f", fg="white",
                  width=20, height=2,
                  command=self.launch_app).pack(pady=80)

    def launch_app(self):
        self.intro_frame.destroy()
        self.build_main_ui()
    
    def log_event(self, module, message):
        """Helper to record events for the audit report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.audit_logs.append(f"[{timestamp}] [{module}] {message}")

    # ---------------- Main UI ----------------
    def build_main_ui(self):
        self.custom_wordlist = []
        self.file_hash = None

        sidebar = tk.Frame(self.root, bg="#111", width=240)
        sidebar.place(x=0, y=0, height=650)

        tk.Label(sidebar, text="Security Toolkit", fg="white", bg="#111",
                 font=("Segoe UI", 16, "bold")).pack(pady=20)

        buttons = [
            ("Password Strength", self.show_strength),
            ("Password Cracking", self.show_cracking),
            ("Dictionary Generator", self.show_dictionary),
            ("Linux Shadow Extraction", self.show_shadow),
            ("Windows SAM Extraction", self.show_sam),
            ("Dictionary Attack (File)", self.show_file_attack),
            ("Generate Audit Report", self.show_report), # Added per PDF Requirement 5
        ]

        for text, cmd in buttons:
            tk.Button(sidebar, text=text, command=cmd, fg="white", bg="#222",
                      font=("Segoe UI", 11), relief="flat", height=2)\
                .pack(fill="x", padx=15, pady=6)

        self.main = tk.Frame(self.root, bg="#1e1e1e")
        self.main.place(x=240, y=0, width=810, height=650)

        self.show_strength()

    def clear_main(self):
        for widget in self.main.winfo_children():
            widget.destroy()

    # ---------------- TOOLS ----------------

    def show_strength(self):
        self.clear_main()
        tk.Label(self.main, text="Password Strength Analyzer", fg="white", bg="#1e1e1e",
                 font=("Segoe UI", 18, "bold")).pack(pady=20)

        entry = tk.Entry(self.main, width=40, font=("Segoe UI", 12), show="*")
        entry.pack(pady=10)

        output = tk.Label(self.main, fg="cyan", bg="#1e1e1e", font=("Segoe UI", 12))
        output.pack(pady=10)

        def analyze():
            pwd = entry.get()
            entropy, strength = password_strength(pwd)
            output.config(text=f"Entropy: {entropy:.2f} | Strength: {strength}")
            self.log_event("STRENGTH", f"Analyzed password. Entropy: {entropy:.2f}, Strength: {strength}")

        tk.Button(self.main, text="Analyze Password", command=analyze,
                  bg="#007acc", fg="white").pack(pady=10)

    def show_cracking(self):
        self.clear_main()
        tk.Label(self.main, text="Password Cracking Simulation", fg="white", bg="#1e1e1e",
                 font=("Segoe UI", 18, "bold")).pack(pady=15)

        entry = tk.Entry(self.main, width=40, font=("Segoe UI", 12), show="*")
        entry.pack(pady=5)

        console = tk.Text(self.main, height=10, bg="black", fg="lime")
        console.pack(padx=20, pady=10, fill="x")

        progress = ttk.Progressbar(self.main, orient="horizontal", length=500, mode="determinate")
        progress.pack(pady=5)

        def log(msg):
            console.insert(tk.END, msg + "\n")
            console.see(tk.END)

        def upload_wordlist():
            file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
            if not file:
                return
            with open(file, "r") as f:
                self.custom_wordlist = [line.strip() for line in f if line.strip()]
            log(f"Wordlist loaded: {file}")
            self.log_event("CRACKING", f"Loaded wordlist: {file}")

        def start_attack():
            progress["value"] = 0
            console.delete(1.0, tk.END)

            def run_attack():
                pwd = entry.get()
                target_hash = hash_password(pwd)
                default_words = ["password", "admin", "user", "test"]
                combined = default_words + self.custom_wordlist
                wordlist = generate_dictionary(combined)

                log("Starting dictionary attack...")
                cracked = dictionary_attack(
                    target_hash, wordlist,
                    lambda p: progress.after(0, lambda: progress.configure(value=p))
                )

                if not cracked:
                    log("Dictionary failed. Trying brute-force...")
                    cracked = brute_force_attack(target_hash)

                if cracked:
                    log(f"Password cracked: {cracked}")
                    self.log_event("CRACKING", f"Success! Password cracked: {cracked}")
                else:
                    log("Password not cracked")
                    self.log_event("CRACKING", "Failed to crack password")

            threading.Thread(target=run_attack).start()

        tk.Button(self.main, text="Upload Wordlist", command=upload_wordlist,
                  bg="#5bc0de", fg="black").pack(pady=5)

        tk.Button(self.main, text="Start Attack Simulation", command=start_attack,
                  bg="#d9534f", fg="white").pack(pady=10)

    def show_dictionary(self):
        self.clear_main()
        tk.Label(self.main, text="Dictionary Generator", fg="white", bg="#1e1e1e",
                 font=("Segoe UI", 18, "bold")).pack(pady=20)

        entry = tk.Entry(self.main, width=50, font=("Segoe UI", 12))
        entry.pack(pady=10)

        status = tk.Label(self.main, fg="cyan", bg="#1e1e1e")
        status.pack(pady=10)

        def generate():
            words = entry.get().split(",")
            wordlist = generate_dictionary(words)
            file = filedialog.asksaveasfilename(defaultextension=".txt")
            if file:
                with open(file, "w") as f:
                    for w in wordlist:
                        f.write(w + "\n")
                status.config(text=f"Dictionary saved ({len(wordlist)} words)")
                self.log_event("DICTIONARY", f"Generated wordlist with {len(wordlist)} words")

        tk.Button(self.main, text="Generate Dictionary File", command=generate,
                  bg="#5cb85c", fg="white").pack(pady=10)

    def show_shadow(self):
        self.clear_main()
        tk.Label(self.main, text="Linux Shadow Hash Extraction", fg="white", bg="#1e1e1e",
                 font=("Segoe UI", 18, "bold")).pack(pady=10)

        tk.Label(self.main, text="Shadow File Location: /etc/shadow",
                 fg="orange", bg="#1e1e1e").pack()

        console = tk.Text(self.main, height=15, bg="black", fg="lime")
        console.pack(padx=20, pady=10, fill="x")

        def load_shadow():
            file = filedialog.askopenfilename()
            if not file:
                return
            console.delete(1.0, tk.END)
            with open(file, "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) > 1:
                        # Modified to show Algorithm (Scope B)
                        algo = identify_hash_algo(parts[1])
                        console.insert(tk.END, f"User: {parts[0]} | Algo: {algo} | Hash: {parts[1]}\n")
            self.log_event("HASH_EXTRACT", f"Loaded Linux Shadow file: {file}")

        tk.Button(self.main, text="Load Shadow File", command=load_shadow,
                  bg="#f0ad4e", fg="black").pack(pady=10)

    def show_sam(self):
        self.clear_main()
        tk.Label(self.main, text="Windows SAM Hash Extraction", fg="white", bg="#1e1e1e",
                 font=("Segoe UI", 18, "bold")).pack(pady=10)

        tk.Label(self.main, text="SAM File Location: C:\\Windows\\System32\\config\\SAM",
                 fg="orange", bg="#1e1e1e").pack()

        console = tk.Text(self.main, height=15, bg="black", fg="lime")
        console.pack(padx=20, pady=10, fill="x")

        def load_sam():
            file = filedialog.askopenfilename()
            if not file:
                return
            console.delete(1.0, tk.END)
            with open(file, "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) >= 4:
                        # Windows uses NTLM by default
                        console.insert(tk.END, f"User: {parts[0]} | Algo: NTLM | Hash: {parts[3]}\n")
            self.log_event("HASH_EXTRACT", f"Loaded Windows SAM file: {file}")

        tk.Button(self.main, text="Load SAM File", command=load_sam,
                  bg="#5bc0de", fg="black").pack(pady=10)

    def show_file_attack(self):
        self.clear_main()
        tk.Label(self.main, text="Dictionary Attack (File)", fg="white", bg="#1e1e1e",
                 font=("Segoe UI", 18, "bold")).pack(pady=15)

        console = tk.Text(self.main, height=14, bg="black", fg="lime")
        console.pack(padx=20, pady=10, fill="x")

        progress = ttk.Progressbar(self.main, orient="horizontal", length=500, mode="determinate")
        progress.pack(pady=5)

        button_frame = tk.Frame(self.main, bg="#1e1e1e")
        button_frame.pack(pady=10)

        def log(msg):
            console.insert(tk.END, msg + "\n")
            console.see(tk.END)

        def upload_file():
            file = filedialog.askopenfilename()
            if not file:
                return
            with open(file, "r") as f:
                for line in f:
                    if "PASSWORD_HASH=" in line:
                        self.file_hash = line.strip().split("=")[1]
                        log(f"File loaded: {file}")
                        log("Password hash extracted successfully")
                        self.log_event("FILE_ATTACK", f"Loaded hash from file: {file}")
                        return
            log("No password hash found in file")

        def upload_wordlist():
            file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
            if not file:
                return
            with open(file, "r") as f:
                self.custom_wordlist = [line.strip() for line in f if line.strip()]
            log(f"Wordlist loaded: {file}")

        def start_attack():
            if not self.file_hash or not self.custom_wordlist:
                log("Upload both file and wordlist first")
                return

            progress["value"] = 0

            def run_attack():
                log("Starting dictionary attack on file...")
                cracked = dictionary_attack(
                    self.file_hash, self.custom_wordlist,
                    lambda p: progress.after(0, lambda: progress.configure(value=p))
                )

                if cracked:
                    log(f"Password found: {cracked}")
                    self.log_event("FILE_ATTACK", f"Cracked file hash: {cracked}")
                else:
                    log("Password not found in wordlist")
                    self.log_event("FILE_ATTACK", "Failed to crack file hash")

            threading.Thread(target=run_attack).start()

        tk.Button(button_frame, text="Upload File", command=upload_file,
                  bg="#f0ad4e", fg="black", width=20).grid(row=0, column=0, padx=10)

        tk.Button(button_frame, text="Upload Wordlist", command=upload_wordlist,
                  bg="#5bc0de", fg="black", width=20).grid(row=0, column=1, padx=10)

        tk.Button(self.main, text="Start Dictionary Attack", command=start_attack,
                  bg="#d9534f", fg="white", width=30).pack(pady=15)
    
    # ---------------- NEW FEATURE: Report Generation ----------------
    def show_report(self):
        self.clear_main()
        tk.Label(self.main, text="Security Audit Report", fg="white", bg="#1e1e1e",
                 font=("Segoe UI", 18, "bold")).pack(pady=20)

        preview = tk.Text(self.main, height=18, bg="#222", fg="white", font=("Consolas", 10))
        preview.pack(padx=20, pady=10, fill="x")

        preview.insert(tk.END, "--- SESSION AUDIT LOG ---\n")
        if not self.audit_logs:
            preview.insert(tk.END, "No actions recorded yet.\n")
        else:
            for log in self.audit_logs:
                preview.insert(tk.END, log + "\n")

        def save_report():
            file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
            if file:
                with open(file, "w") as f:
                    f.write("PASSWORD AUDIT & ATTACK SUITE - FINAL REPORT\n")
                    f.write("============================================\n")
                    f.write(f"Generated on: {datetime.datetime.now()}\n\n")
                    f.write("Session Logs:\n")
                    for log in self.audit_logs:
                        f.write(log + "\n")
                    f.write("\nEnd of Report.")
                messagebox.showinfo("Success", "Audit Report Generated Successfully!")

        tk.Button(self.main, text="Download Report (.txt)", command=save_report,
                  bg="#d9534f", fg="white", font=("Segoe UI", 12, "bold")).pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAuditApp(root)
    root.mainloop()
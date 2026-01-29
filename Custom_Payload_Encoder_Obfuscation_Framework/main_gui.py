import tkinter as tk
from tkinter import ttk, messagebox, font, filedialog
import datetime
import platform
import os

# Import your modules
from modules.encoder import Encoder
from modules.obfuscator import Obfuscator
from modules.evasion_test import EvasionTester
from modules.extractor import StringExtractor

class PayloadApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Payload Obfuscation Framework")
        self.root.geometry("950x800")
        
        # Theme & Colors
        self.bg_color = "#f0f0f0"
        self.accent_color = "#2c3e50" 
        self.highlight_color = "#d9534f"
        self.root.configure(bg=self.bg_color)

        # Fonts
        self.title_font = font.Font(family="Consolas", size=18, weight="bold")
        self.label_font = font.Font(family="Helvetica", size=10)
        self.btn_font = font.Font(family="Helvetica", size=10, weight="bold")

        # --- TAB SYSTEM SETUP ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=self.bg_color)
        style.configure("TNotebook.Tab", padding=[12, 5], font=('Helvetica', 10, 'bold'))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)

        # Create 5 Tab Frames
        self.tab_home = tk.Frame(self.notebook, bg="white")
        self.tab_encoder = tk.Frame(self.notebook, bg="#f4f4f4")      # Tab 2: Encoding
        self.tab_obfuscator = tk.Frame(self.notebook, bg="#f4f4f4")   # Tab 3: Obfuscation
        self.tab_extractor = tk.Frame(self.notebook, bg="#f4f4f4")    # Tab 4: Analysis
        self.tab_about = tk.Frame(self.notebook, bg="white")          # Tab 5: About

        # Add Tabs
        self.notebook.add(self.tab_home, text='  🏠 Dashboard  ')
        self.notebook.add(self.tab_encoder, text='  🔐 Encoders & Decoders  ')
        self.notebook.add(self.tab_obfuscator, text='  🧩 String Obfuscation  ')
        self.notebook.add(self.tab_extractor, text='  🔍 Binary Analysis  ')
        self.notebook.add(self.tab_about, text='  ℹ️ About  ')

        # --- BUILD PAGES ---
        self.build_home_page()
        self.build_encoder_page()     
        self.build_obfuscator_page()  
        self.build_extractor_page()
        self.build_about_page()
        
        # Start Clock
        self.update_clock()

    # PAGE 1: DASHBOARD
    def build_home_page(self):
        # 1. TOP BANNER
        banner_frame = tk.Frame(self.tab_home, bg=self.accent_color, height=150)
        banner_frame.pack(fill="x")
        
        ascii_logo = """
      ▄████████    ▄███████▄    ▄████████  ▄██████▄     ▄████████ 
     ███    ███   ███    ███   ███    ███ ███    ███   ███    ███ 
     ███    █▀    ███    ███   ███    █▀  ███    ███   ███    █▀  
     ███          ███    ███  ▄███▄▄▄     ███    ███  ▄███▄▄▄     
    ▀███         ▀█████████▀  ▀▀███▀▀▀     ███    ███ ▀▀███▀▀▀     
     ███     ███  ███          ███    █▄  ███    ███   ███        
     ███     ███  ███          ███    ███ ███    ███   ███        
      ████████▀  ▄████▀        ██████████  ▀██████▀    ███        
        """
        tk.Label(banner_frame, text=ascii_logo, font=("Consolas", 8), bg=self.accent_color, fg="#00ff00").pack(pady=(10, 5))
        tk.Label(banner_frame, text="Custom Payload Encoder & Obfuscation Framework", font=("Arial", 14, "bold"), bg=self.accent_color, fg="white").pack(pady=(0, 15))

        # 2. MAIN CONTENT
        content_frame = tk.Frame(self.tab_home, bg="white")
        content_frame.pack(fill="both", expand=True, padx=40, pady=20)

        tk.Label(content_frame, text="Select a Module:", font=("Helvetica", 14, "bold"), bg="white", fg="#333").pack(anchor="w", pady=(0, 10))

        # 3. NAVIGATION BUTTONS
        btn_frame = tk.Frame(content_frame, bg="white")
        btn_frame.pack(fill="x", pady=10)

        self.create_nav_btn(btn_frame, "🔐 Encoders & Decoders", "Base64, ROT13, XOR operations", self.tab_encoder)
        self.create_nav_btn(btn_frame, "🧩 String Obfuscation", "Split, Reverse, Hex, Poly, Subs", self.tab_obfuscator)
        self.create_nav_btn(btn_frame, "🔍 Binary Analysis", "PE/ELF Strings & YARA", self.tab_extractor)

        # 4. SYSTEM STATUS FOOTER
        footer_frame = tk.Frame(self.tab_home, bg="#eee", height=30)
        footer_frame.pack(side="bottom", fill="x")
        
        user = os.getlogin() if hasattr(os, 'getlogin') else "Admin"
        os_info = f"{platform.system()} {platform.release()}"
        
        self.status_label = tk.Label(footer_frame, text=f"User: {user} | OS: {os_info} | System: Online", font=("Consolas", 9), bg="#eee", fg="#555")
        self.status_label.pack(side="right", padx=10, pady=5)
        
        self.time_label = tk.Label(footer_frame, text="", font=("Consolas", 9), bg="#eee", fg="#555")
        self.time_label.pack(side="left", padx=10, pady=5)

    def create_nav_btn(self, parent, title, desc, tab):
        f = tk.Frame(parent, bg="#e9ecef", bd=1, relief="solid", padx=10, pady=10)
        f.pack(side="left", fill="both", expand=True, padx=10)
        tk.Label(f, text=title, font=("Arial", 12, "bold"), bg="#e9ecef").pack()
        tk.Label(f, text=desc, font=("Arial", 9), bg="#e9ecef", fg="#555").pack(pady=5)
        tk.Button(f, text="Open Module", bg="#0275d8", fg="white", command=lambda: self.notebook.select(tab)).pack(pady=5)

    def update_clock(self):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=f"Time: {now}")
        self.root.after(1000, self.update_clock)

    def build_encoder_page(self):
        content = tk.Frame(self.tab_encoder, padx=20, pady=20, bg="#f4f4f4")
        content.pack(fill="both", expand=True)

        tk.Label(content, text="Encoding & Decoding Engine", font=("Helvetica", 14, "bold"), bg="#f4f4f4").pack(anchor="w", pady=(0, 10))

        # Input
        tk.Label(content, text="Input Text / Payload:", font=self.btn_font, bg="#f4f4f4").pack(anchor="w")
        self.enc_input = tk.Text(content, height=4, width=80, font=("Consolas", 10), bd=2, relief="flat")
        self.enc_input.pack(pady=5, fill="x")

        # Controls
        opts = tk.LabelFrame(content, text="Settings", font=self.btn_font, padx=15, pady=15, bg="white")
        opts.pack(pady=10, fill="x")

        # Mode Selection
        tk.Label(opts, text="Mode:", font=self.label_font, bg="white").grid(row=0, column=0, sticky="w")
        self.enc_mode = tk.StringVar(value="encode")
        tk.Radiobutton(opts, text="Encode", variable=self.enc_mode, value="encode", bg="white").grid(row=0, column=1)
        tk.Radiobutton(opts, text="Decode", variable=self.enc_mode, value="decode", bg="white").grid(row=0, column=2)

        # Method Selection
        tk.Label(opts, text="Algorithm:", font=self.label_font, bg="white").grid(row=0, column=3, padx=(20, 5))
        self.enc_method = ttk.Combobox(opts, state="readonly", values=('Base64', 'ROT13', 'XOR'))
        self.enc_method.current(0)
        self.enc_method.grid(row=0, column=4)

        # XOR Key
        tk.Label(opts, text="XOR Key:", font=self.label_font, bg="white").grid(row=1, column=0, sticky="w", pady=10)
        self.enc_key = tk.Entry(opts, width=20, bd=1, relief="solid")
        self.enc_key.grid(row=1, column=1, columnspan=2, sticky="w", pady=10)

        # Run Button
        tk.Button(content, text="⚡ RUN OPERATION", bg="#0275d8", fg="white", font=self.btn_font, 
                  padx=15, pady=10, command=self.run_encoder).pack(pady=10)

        # Output
        tk.Label(content, text="Result:", font=self.btn_font, bg="#f4f4f4").pack(anchor="w")
        self.enc_output = tk.Text(content, height=4, width=80, font=("Consolas", 10), bd=2, relief="flat", bg="#e9ecef")
        self.enc_output.pack(pady=5, fill="x")

        # Evasion Check
        self.enc_status = tk.Label(content, text="Ready", font=("Arial", 10), bg="#f4f4f4", fg="gray")
        self.enc_status.pack(pady=5)

    # PAGE 3: STRING OBFUSCATION
    def build_obfuscator_page(self):
        content = tk.Frame(self.tab_obfuscator, padx=20, pady=20, bg="#f4f4f4")
        content.pack(fill="both", expand=True)

        tk.Label(content, text="String Obfuscation Generator", font=("Helvetica", 14, "bold"), bg="#f4f4f4").pack(anchor="w", pady=(0, 10))

        # Input
        tk.Label(content, text="Raw Payload (e.g. powershell.exe):", font=self.btn_font, bg="#f4f4f4").pack(anchor="w")
        self.obf_input = tk.Text(content, height=4, width=80, font=("Consolas", 10), bd=2, relief="flat")
        self.obf_input.pack(pady=5, fill="x")

        # Controls
        opts = tk.LabelFrame(content, text="Technique Selection", font=self.btn_font, padx=15, pady=15, bg="white")
        opts.pack(pady=10, fill="x")

        tk.Label(opts, text="Technique:", font=self.label_font, bg="white").grid(row=0, column=0, padx=5)
        self.obf_method = ttk.Combobox(opts, state="readonly", width=35, values=(
            'String Splitting ("a"+"b")', 
            'Reverse String (Reversible)', 
            'Hex Escape Sequence (\\x41)', 
            'Random Char Insertion',
            'Polymorphic Junk (Random Hash)',
            'Command Substitution (Aliases)'
        ))
        self.obf_method.current(0)
        self.obf_method.grid(row=0, column=1, padx=10)

        # Run Button
        tk.Button(content, text="🧩 OBFUSCATE PAYLOAD", bg="#d9534f", fg="white", font=self.btn_font, 
                  padx=15, pady=10, command=self.run_obfuscator).pack(pady=10)

        # Output
        tk.Label(content, text="Obfuscated Result:", font=self.btn_font, bg="#f4f4f4").pack(anchor="w")
        self.obf_output = tk.Text(content, height=4, width=80, font=("Consolas", 10), bd=2, relief="flat", bg="#e9ecef")
        self.obf_output.pack(pady=5, fill="x")

        # Evasion Status
        self.obf_status = tk.Label(content, text="Ready", font=("Arial", 10), bg="#f4f4f4", fg="gray")
        self.obf_status.pack(pady=5)

    # PAGE 4: BINARY ANALYSIS
    def build_extractor_page(self):
        content = tk.Frame(self.tab_extractor, padx=20, pady=20, bg="#f4f4f4")
        content.pack(fill="both", expand=True)
        
        tk.Button(content, text="📂 SELECT FILE TO ANALYZE", bg="#f0ad4e", fg="white", font=self.btn_font, 
                  padx=20, pady=10, command=self.run_full_analysis).pack(pady=10)
        
        self.file_status_lbl = tk.Label(content, text="No file loaded", bg="#f4f4f4")
        self.file_status_lbl.pack()

        # Split View: Strings & YARA
        pane = tk.PanedWindow(content, orient=tk.VERTICAL)
        pane.pack(fill="both", expand=True, pady=10)

        # Top: YARA
        f1 = tk.LabelFrame(pane, text="YARA Detections", fg="#d9534f", bg="white")
        self.yara_list = tk.Listbox(f1, height=5, font=("Consolas", 9), fg="#c9302c", bg="#fff0f0")
        self.yara_list.pack(fill="both", expand=True)
        pane.add(f1)

        # Bottom: Strings
        f2 = tk.LabelFrame(pane, text="Extracted Strings", bg="white")
        self.str_text = tk.Text(f2, height=10, font=("Consolas", 9), bg="#2d2d2d", fg="#00ff00")
        self.str_text.pack(fill="both", expand=True)
        pane.add(f2)

    # PAGE 5: ABOUT
    
    def build_about_page(self):
        # Main Container with White Background
        container = tk.Frame(self.tab_about, bg="white")
        container.pack(fill="both", expand=True, padx=50, pady=30)

        # 1. Header Title
        tk.Label(container, text="About the Framework", font=("Helvetica", 24, "bold"), bg="white", fg="#2c3e50").pack(pady=(0, 20))
        tk.Label(container, text="Custom Payload Encoder & Obfuscation Framework (CPEOF)", font=("Arial", 10), bg="white", fg="gray").pack()

        # 2. Developer Profile Card (Your Requested Info)
        profile_frame = tk.LabelFrame(container, text="  Project Identity  ", font=("Arial", 11, "bold"), bg="white", fg="#d9534f", bd=2, relief="groove")
        profile_frame.pack(fill="x", pady=30, ipady=10)

        # Formatted Text Block
        info_text = (
            "👤   Developed by  :   GuntaSubham\n\n"
            "🎓   Context       :   Cyber Security Internship Project\n\n"
            "🎯   Objective     :   To study and demonstrate advanced\n"
            "                        Encoding, Decoding, Obfuscation,\n"
            "                        and Evasion techniques."
        )
        
        # Using Consolas font makes it look like code/terminal text
        tk.Label(profile_frame, text=info_text, font=("Consolas", 12), bg="white", justify="left", fg="#333").pack(padx=20, pady=10)

        # 3. Technical Stats (To fill the space nicely)
        stats_frame = tk.Frame(container, bg="#f8f9fa", bd=1, relief="solid")
        stats_frame.pack(fill="x", pady=10, ipady=15)
        
        tk.Label(stats_frame, text="System Architecture", font=("Arial", 10, "bold"), bg="#f8f9fa", fg="#555").pack(pady=(5, 10))
        
        # Grid for stats
        grid_frame = tk.Frame(stats_frame, bg="#f8f9fa")
        grid_frame.pack()
        
        self.add_stat(grid_frame, "Language", "Python 3", 0)
        self.add_stat(grid_frame, "Interface", "Tkinter GUI", 1)
        self.add_stat(grid_frame, "Modules", "4 Core Engines", 2)
        self.add_stat(grid_frame, "Build", "v1.0 Stable", 3)

        # 4. Bottom Footer
        tk.Label(container, text="© 2025 CPEOF Project | Educational Security Research", font=("Arial", 9), bg="white", fg="#999").pack(side="bottom")

    # Helper function for the stats row
    def add_stat(self, parent, label, value, col):
        f = tk.Frame(parent, bg="#f8f9fa", padx=20)
        f.grid(row=0, column=col, padx=10)
        tk.Label(f, text=label, font=("Arial", 8), bg="#f8f9fa", fg="#888").pack()
        tk.Label(f, text=value, font=("Arial", 10, "bold"), bg="#f8f9fa", fg="#333").pack()
    # LOGIC: ENCODER TAB
    def run_encoder(self):
        raw = self.enc_input.get("1.0", tk.END).strip()
        if not raw: return
        
        mode = self.enc_mode.get()
        method = self.enc_method.get()
        key = self.enc_key.get().strip()
        
        encoder = Encoder(raw)
        res = ""
        
        try:
            if method == "Base64": res = encoder.to_base64() if mode == "encode" else encoder.from_base64()
            elif method == "ROT13": res = encoder.to_rot13() if mode == "encode" else encoder.from_rot13()
            elif method == "XOR": res = encoder.xor_encrypt(key) # Symmetric
            
            self.enc_output.delete("1.0", tk.END)
            self.enc_output.insert(tk.END, res)
            
            # Check Evasion
            tester = EvasionTester()
            if mode == "encode":
                is_det, msg = tester.scan(res)
                self.enc_status.config(text=f"Evasion Status: {msg}", fg="red" if is_det else "green")
            else:
                self.enc_status.config(text="Decoded Successfully", fg="blue")
                
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # LOGIC: OBFUSCATOR TAB
    def run_obfuscator(self):
        raw = self.obf_input.get("1.0", tk.END).strip()
        if not raw: return
        
        method = self.obf_method.get()
        obf = Obfuscator(raw)
        res = ""
        
        try:
            if "Splitting" in method: res = obf.split_string()
            elif "Reverse" in method: res = obf.reverse_string()
            elif "Hex" in method: res = obf.escape_sequence()   
            elif "Random" in method: res = obf.insert_random_chars()
            elif "Polymorphic" in method: res = obf.polymorphic_junk()
            elif "Substitution" in method: res = obf.command_substitution()
            
            self.obf_output.delete("1.0", tk.END)
            self.obf_output.insert(tk.END, res)
            
            # Check Evasion
            tester = EvasionTester()
            is_det, msg = tester.scan(res)
            self.obf_status.config(text=f"Evasion Status: {msg}", fg="red" if is_det else "green")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # LOGIC: ANALYSIS TAB
    def run_full_analysis(self):
        path = filedialog.askopenfilename()
        if not path: return
        self.file_status_lbl.config(text=f"Loaded: {os.path.basename(path)}")
        
        # YARA
        self.yara_list.delete(0, tk.END)
        detections = EvasionTester().scan_file(path)
        for d in detections: self.yara_list.insert(tk.END, f"⚠️ {d}")
        if not detections: self.yara_list.insert(tk.END, "✅ Clean File")
        
        # Strings
        self.str_text.delete("1.0", tk.END)
        self.str_text.insert(tk.END, StringExtractor().extract_from_file(path))

if __name__ == "__main__":
    root = tk.Tk()
    app = PayloadApp(root)
    root.mainloop()
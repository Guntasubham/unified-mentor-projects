import psutil
import time
import json
import subprocess
import winreg
import threading
import tkinter as tk
import ctypes  # Required for Taskbar Icon Fix
from tkinter import ttk, messagebox
from pathlib import Path
from datetime import datetime
import os
import sys

# ================= FILE =================
LOG_FILE = Path("monitor_logs.json")

# ================= CONFIG =================
SUSPICIOUS_PARENTS = {
    "explorer.exe": ["powershell.exe", "cmd.exe"],
    "winword.exe": ["powershell.exe"],
    "excel.exe": ["cmd.exe"]
}

SUSPICIOUS_PATHS = ["\\appdata\\", "\\temp\\", "\\downloads\\"]

KNOWN_MANAGEMENT_TOOLS = [
    "immybot", "screenconnect", "teamviewer", "anydesk"
]

STARTUP_KEYS = [
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

# ================= STATE =================
seen_pids = set()
seen_startup = set()
seen_services = set()
seen_tasks = set()
seen_binaries = set()
total_alerts = 0  # Track total alerts for status bar

# ================= AGENT HELPERS =================
def log_event(event):
    global total_alerts
    logs = []
    if LOG_FILE.exists():
        try:
            logs = json.loads(LOG_FILE.read_text())
        except:
            pass
    logs.append(event)
    total_alerts = len(logs)
    LOG_FILE.write_text(json.dumps(logs, indent=4))

def classify_trust(name, path):
    lname = name.lower()
    if any(tool in lname for tool in KNOWN_MANAGEMENT_TOOLS):
        return "Management"
    if path.startswith("c:\\windows"):
        return "System"
    return "Unknown"

def suspicious_path(path):
    return any(p in path.lower() for p in SUSPICIOUS_PATHS)

# ================= AGENT LOGIC =================
def check_process(proc):
    reasons = []
    risk = 0
    try:
        name = proc.name().lower()
        path = proc.exe().lower()
        parent = psutil.Process(proc.ppid()).name().lower()
    except:
        return

    if parent in SUSPICIOUS_PARENTS and name in SUSPICIOUS_PARENTS[parent]:
        reasons.append(f"Suspicious parent-child: {parent} -> {name}")
        risk += 40

    if suspicious_path(path):
        reasons.append("Executed from user-writable directory")
        risk += 30

    binary_id = f"{name}|{path}"
    if binary_id not in seen_binaries:
        seen_binaries.add(binary_id)
        reasons.append("First time this executable was observed")
        risk += 15

    if not path.startswith(("c:\\windows", "c:\\program files")):
        reasons.append("Executable running outside standard directories")
        risk += 15

    trust = classify_trust(name, path)
    if trust == "Unknown":
        reasons.append("Unknown or unmanaged process")
        risk += 20

    if risk >= 30:
        log_event({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "Process Execution Detected",
            "process": name,
            "parent": parent,
            "path": path,
            "trust": trust,
            "risk_score": risk,
            "reasons": reasons
        })

def check_startup_registry():
    for hive, key_path in STARTUP_KEYS:
        try:
            key = winreg.OpenKey(hive, key_path)
        except:
            continue
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                i += 1
            except:
                break
            uid = f"{hive}-{key_path}-{name}"
            if uid in seen_startup:
                continue
            seen_startup.add(uid)
            if suspicious_path(value):
                log_event({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "Startup Persistence Detected",
                    "entry": name,
                    "command": value,
                    "trust": "Unknown",
                    "risk_score": 60,
                    "reasons": ["Startup entry from user-writable directory"]
                })

def check_services():
    for svc in psutil.win_service_iter():
        name = svc.name()
        if name in seen_services:
            continue
        seen_services.add(name)
        try:
            path = svc.as_dict().get("binpath", "").lower()
        except:
            continue
        if suspicious_path(path):
            log_event({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "Service Persistence Detected",
                "service": name,
                "path": path,
                "risk_score": 60,
                "reasons": ["Service created from user-writable directory"]
            })

def check_scheduled_tasks():
    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            stderr=subprocess.DEVNULL,
            shell=True,
            text=True
        )
    except:
        return
    for line in output.splitlines()[1:]:
        if line in seen_tasks:
            continue
        seen_tasks.add(line)
        if any(p in line.lower() for p in SUSPICIOUS_PATHS):
            log_event({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "Scheduled Task Persistence Detected",
                "details": line,
                "risk_score": 50,
                "reasons": ["Scheduled task executing from suspicious path"]
            })

def agent_loop():
    while True:
        try:
            for p in psutil.process_iter(['pid']):
                if p.pid not in seen_pids:
                    seen_pids.add(p.pid)
                    check_process(p)
            check_startup_registry()
            check_services()
            check_scheduled_tasks()
        except Exception as e:
            pass
        time.sleep(3)

# ================= STARTUP INSTALL =================
def ensure_startup():
    task = "EndpointMonitorAgent"
    try:
        subprocess.check_output(["schtasks", "/query", "/tn", task],
                                stderr=subprocess.DEVNULL, shell=True)
        return
    except:
        pass

    exe = os.path.abspath(sys.argv[0])
    try:
        # Added stderr=subprocess.DEVNULL to silence 'Access is denied' if not Admin
        subprocess.check_call(
            ["schtasks", "/create", "/f",
             "/sc", "onlogon",
             "/rl", "highest",
             "/tn", task,
             "/tr", f'"{exe}"'],
            shell=True,
            stderr=subprocess.DEVNULL 
        )
    except:
        pass

# ================= GUI =================
BG_DARK = "#0d1117"
BG_PANEL = "#161b22"
TEXT_MAIN = "#c9d1d9"
ACCENT_GREEN = "#238636"
ACCENT_HOVER = "#2ea043"
TEXT_ACCENT = "#58a6ff"
BORDER = "#30363d"

RISK_COLORS = {
    "info": "#161b22",
    "review": "#4d4206",
    "suspicious": "#5e2e09",
    "critical": "#5c0e13"
}

class MonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # --- TASKBAR & ICON FIX START ---
        # 1. Force Windows to treat this as a standalone app (not Python)
        try:
            myappid = 'sentinel.monitor.agent.v1.0'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception as e:
            print(f"Taskbar fix warning: {e}")
        
        self.title("🛡️ Sentinel Endpoint Monitor")
        self.geometry("1300x700")
        self.configure(bg=BG_DARK)
        
        # 2. Robust Icon Loading (Finds file even if run from different folder)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(script_dir, "shield.ico")

        if os.path.exists(icon_path):
            try:
                # 'default=True' applies the icon to the Taskbar and all child windows
                self.iconbitmap(default=icon_path)
            except Exception as e:
                print(f"Icon error: {e}")
        else:
            print(f"⚠️ Warning: shield.ico not found at {icon_path}")
        # --- TASKBAR & ICON FIX END ---

        # Style Configuration
        style = ttk.Style(self)
        style.theme_use("clam")
        
        style.configure("Treeview", 
                        background=BG_PANEL, 
                        foreground=TEXT_MAIN, 
                        fieldbackground=BG_PANEL,
                        rowheight=28,
                        borderwidth=0)
        
        style.configure("Treeview.Heading", 
                        background=BG_DARK, 
                        foreground=TEXT_ACCENT,
                        font=("Segoe UI", 10, "bold"),
                        borderwidth=1)
        
        style.map("Treeview", background=[("selected", "#1f6feb")])

        style.configure("TButton", 
                        background=BG_PANEL, 
                        foreground=TEXT_MAIN, 
                        borderwidth=1,
                        focusthickness=3,
                        focuscolor="none")
        style.map("TButton", background=[("active", "#30363d")])
        
        style.configure("Accent.TButton", 
                        background=ACCENT_GREEN, 
                        foreground="white",
                        font=("Segoe UI", 9, "bold"))
        style.map("Accent.TButton", background=[("active", ACCENT_HOVER)])

        # --- TOP CONTROL BAR ---
        top = tk.Frame(self, bg=BG_DARK, pady=10, padx=10)
        top.pack(fill=tk.X)

        tk.Label(top, text="PROCESS MONITOR", fg=TEXT_ACCENT, bg=BG_DARK, 
                 font=("Consolas", 18, "bold")).pack(side=tk.LEFT, padx=(0, 20))

        tk.Label(top, text="🔍 Filter:", fg=TEXT_MAIN, bg=BG_DARK).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(top, textvariable=self.search_var, bg=BG_PANEL, fg=TEXT_MAIN, insertbackground="white")
        self.search_entry.pack(side=tk.LEFT, padx=5, fill=tk.Y)
        self.search_entry.bind("<KeyRelease>", self.filter_logs)

        ttk.Button(top, text="Refresh Logs", command=self.load_logs).pack(side=tk.RIGHT, padx=5)
        ttk.Button(top, text="Risk Guide", command=self.show_risk).pack(side=tk.RIGHT, padx=5)
        ttk.Button(top, text="Event Details", command=self.show_details, style="Accent.TButton").pack(side=tk.RIGHT, padx=5)

        # --- MAIN SPLIT VIEW ---
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # LEFT: ALERTS
        left_frame = tk.Frame(paned, bg=BG_DARK)
        paned.add(left_frame, weight=3)
        
        tk.Label(left_frame, text="⚠️ Security Alerts", bg=BG_DARK, fg=TEXT_MAIN, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0,5))

        cols = ("time", "type", "process", "parent", "risk")
        self.tree = ttk.Treeview(left_frame, columns=cols, show="headings", selectmode="browse")
        
        self.tree.heading("time", text="TIMESTAMP")
        self.tree.heading("type", text="DETECTION TYPE")
        self.tree.heading("process", text="PROCESS / ENTRY")
        self.tree.heading("parent", text="PARENT")
        self.tree.heading("risk", text="RISK")

        self.tree.column("time", width=140)
        self.tree.column("type", width=180)
        self.tree.column("process", width=140)
        self.tree.column("parent", width=120)
        self.tree.column("risk", width=50, anchor="center")

        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

        for k, v in RISK_COLORS.items():
            self.tree.tag_configure(k, background=v)

        # RIGHT: PROCESS LIST
        right_frame = tk.Frame(paned, bg=BG_DARK)
        paned.add(right_frame, weight=1)

        header_frame = tk.Frame(right_frame, bg=BG_DARK)
        header_frame.pack(fill=tk.X, pady=(0,5))
        tk.Label(header_frame, text="⚙️ Live Processes", bg=BG_DARK, fg=TEXT_MAIN, font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        ttk.Button(header_frame, text="⟳", width=3, command=self.load_processes).pack(side=tk.RIGHT)

        self.proc_list = tk.Listbox(
            right_frame, bg=BG_PANEL, fg=TEXT_MAIN,
            selectbackground="#1f6feb", highlightthickness=0, borderwidth=0
        )
        self.proc_list.pack(fill=tk.BOTH, expand=True)

        # --- STATUS BAR ---
        self.status_var = tk.StringVar()
        self.status_var.set("Agent Status: Active | Monitoring Process, Registry, Services...")
        status_bar = tk.Label(self, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, bg=BG_PANEL, fg="#8b949e", font=("Segoe UI", 9))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.load_logs()
        self.load_processes()
        self.auto_refresh_ui()

    # ---------- GUI FUNCTIONS ----------
    def auto_refresh_ui(self):
        self.load_processes()
        self.update_status()
        self.after(5000, self.auto_refresh_ui)

    def update_status(self):
        global total_alerts
        self.status_var.set(f"Agent Status: Active 🟢 | Total Alerts: {total_alerts} | Last Scan: {datetime.now().strftime('%H:%M:%S')}")

    def load_logs(self):
        self.tree.delete(*self.tree.get_children())
        if not LOG_FILE.exists():
            return
        
        try:
            logs = json.loads(LOG_FILE.read_text())
        except:
            return

        logs.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        global total_alerts
        total_alerts = len(logs)
        self.update_status()

        term = self.search_var.get().lower()

        for e in logs:
            proc_name = str(e.get("process", e.get("entry", ""))).lower()
            evt_type = str(e.get("type", "")).lower()
            
            if term and (term not in proc_name and term not in evt_type):
                continue

            r = e.get("risk_score", 0)
            tag = "info" if r < 40 else "review" if r < 60 else "suspicious" if r < 80 else "critical"
            
            self.tree.insert("", tk.END, values=(
                e.get("timestamp", ""),
                e.get("type", ""),
                e.get("process", e.get("entry", "")),
                e.get("parent", "-"),
                r
            ), tags=(tag,))

    def filter_logs(self, event):
        self.load_logs()

    def load_processes(self):
        y_scroll = self.proc_list.yview()
        self.proc_list.delete(0, tk.END)
        procs = []
        for p in psutil.process_iter(attrs=["name"]):
            try:
                procs.append(p.info["name"])
            except:
                pass
        
        procs.sort(key=str.lower)
        for p_name in procs:
            self.proc_list.insert(tk.END, f" {p_name}")
        self.proc_list.yview_moveto(y_scroll[0])

    def show_details(self):
        sel = self.tree.focus()
        if not sel:
            messagebox.showinfo("Info", "Select an alert first")
            return
        
        item = self.tree.item(sel)
        vals = item['values']
        
        if not LOG_FILE.exists(): return
        logs = json.loads(LOG_FILE.read_text())
        
        target = None
        for log in logs:
            p_name = log.get("process", log.get("entry", ""))
            if log.get("timestamp") == vals[0] and p_name == vals[2]:
                target = log
                break
        
        if not target: return

        popup = tk.Toplevel(self)
        popup.title("Event Analysis")
        popup.geometry("600x500")
        popup.configure(bg=BG_DARK)
        
        # Apply icon to popup too
        script_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(script_dir, "shield.ico")
        if os.path.exists(icon_path):
             popup.iconbitmap(icon_path)

        tk.Label(popup, text=f"Risk Score: {target.get('risk_score')}", 
                 font=("Segoe UI", 14, "bold"), fg="white", bg=BG_DARK).pack(pady=10)

        tk.Label(popup, text="Why was this flagged?", fg=TEXT_ACCENT, bg=BG_DARK).pack(anchor="w", padx=10)
        
        reason_frame = tk.Frame(popup, bg=BG_PANEL, bd=1, relief=tk.SOLID)
        reason_frame.pack(fill=tk.X, padx=10, pady=5)
        
        for r in target.get("reasons", []):
            tk.Label(reason_frame, text=f"• {r}", fg="#ff7b72", bg=BG_PANEL, anchor="w").pack(fill=tk.X, padx=5, pady=2)

        tk.Label(popup, text="Raw Data", fg=TEXT_ACCENT, bg=BG_DARK).pack(anchor="w", padx=10, pady=(10,0))
        text_box = tk.Text(popup, height=15, bg=BG_PANEL, fg=TEXT_MAIN, borderwidth=0)
        text_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        text_box.insert(tk.END, json.dumps(target, indent=4))
        text_box.config(state=tk.DISABLED)

    def show_risk(self):
        messagebox.showinfo("Risk Guide", 
            "0-40: Info (Safe)\n40-60: Review (Unusual parent)\n60-80: Suspicious (Writable paths)\n80+: Critical (Known attack patterns)")

# ================= MAIN =================
if __name__ == "__main__":
    ensure_startup()
    threading.Thread(target=agent_loop, daemon=True).start()
    app = MonitorApp()
    app.mainloop()
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import datetime
import csv
import ctypes
from PIL import Image, ImageTk

from sentinel_engine import SentinelEngine

HEADER_BG = "#2c3e50"
HEADER_FG = "white"
NAV_BTN_COLOR = "#34495e"
ACCENT_COLOR = "#2980b9"

class SentinelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        try:
            myappid = 'student.sentinelshield.waf.v1' 
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception:
            pass

        self.title("SentinelShield: Advanced WAF System")
        self.geometry("1000x700") 
        
        try:
            icon_image = tk.PhotoImage(file="icon.png")
            self.iconphoto(True, icon_image) 
        except Exception:
            print("Warning: icon.png not found. Default icon used.")

        self.configure(bg="#ecf0f1")
        
        self.engine = SentinelEngine()
        
        self.container = tk.Frame(self)
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        
        for F in (HomePage, SimulatorPage, DashboardPage, LogsPage):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("HomePage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()
        if hasattr(frame, "update_view"):
            frame.update_view()

class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        try:
            self.bg_image_raw = Image.open("background.jpg")
            self.bg_image_raw = self.bg_image_raw.resize((1000, 700), Image.Resampling.LANCZOS)
            self.bg_image = ImageTk.PhotoImage(self.bg_image_raw)
            
            bg_label = tk.Label(self, image=self.bg_image)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except Exception:
            print("Warning: background.jpg not found. Using solid color.")
            self.configure(bg="#2c3e50")

        content_frame = tk.Frame(self, bg="white", bd=2, relief="raised")
        content_frame.place(relx=0.5, rely=0.5, anchor="center", width=500, height=450)

        tk.Label(content_frame, text="SentinelShield", font=("Helvetica", 32, "bold"), 
                 bg="white", fg="#2c3e50").pack(pady=(40, 10))
        
        tk.Label(content_frame, text="Intrusion Detection System", 
                 font=("Helvetica", 14), bg="white", fg="#7f8c8d").pack(pady=(0, 30))

        self.create_nav_btn(content_frame, "🚀 Launch Simulator", "SimulatorPage").pack(pady=8, fill="x", padx=40)
        self.create_nav_btn(content_frame, "📊 View Dashboard", "DashboardPage").pack(pady=8, fill="x", padx=40)
        self.create_nav_btn(content_frame, "📝 System Logs", "LogsPage").pack(pady=8, fill="x", padx=40)

        tk.Label(content_frame, text="Final Year Project | 2026", font=("Arial", 9), 
                 bg="white", fg="#bdc3c7").pack(side="bottom", pady=20)

    def create_nav_btn(self, parent, text, page_name):
        return tk.Button(parent, text=text, font=("Arial", 12, "bold"), bg=ACCENT_COLOR, fg="white", 
                         height=2, cursor="hand2", command=lambda: self.controller.show_frame(page_name))

class SimulatorPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg="#ecf0f1")

        self.create_header("Traffic Simulator & Attack Injection")

        content = tk.Frame(self, bg="#ecf0f1", padx=40, pady=20)
        content.pack(fill="both", expand=True)

        tk.Label(content, text="Source IP Address:", bg="#ecf0f1", font=("Arial", 12, "bold")).pack(anchor="w")
        self.ip_entry = ttk.Entry(content, width=40)
        self.ip_entry.pack(anchor="w", pady=5)
        self.ip_entry.insert(0, "192.168.1.105")

        tk.Label(content, text="Request Payload (URL/Body):", bg="#ecf0f1", font=("Arial", 12, "bold")).pack(anchor="w", pady=(20,0))
        self.payload_entry = tk.Text(content, height=5, width=60, font=("Consolas", 10))
        self.payload_entry.pack(anchor="w", pady=5)
        self.payload_entry.insert("1.0", "SELECT * FROM users WHERE id=1")

        ttk.Button(content, text="▶ SEND REQUEST", command=self.send_request).pack(anchor="w", pady=10)
        
        ttk.Separator(content, orient="horizontal").pack(fill="x", pady=20)

        lbl_frame = tk.LabelFrame(content, text="Quick Attack Presets", bg="#ecf0f1", font=("Arial", 10, "bold"), padx=10, pady=10)
        lbl_frame.pack(fill="x")

        ttk.Button(lbl_frame, text="SQL Injection", command=lambda: self.fill("admin' OR 1=1 --")).pack(side="left", padx=5)
        ttk.Button(lbl_frame, text="XSS Attack", command=lambda: self.fill("<script>alert(1)</script>")).pack(side="left", padx=5)
        ttk.Button(lbl_frame, text="Path Traversal", command=lambda: self.fill("../../etc/passwd")).pack(side="left", padx=5)
        ttk.Button(lbl_frame, text="Honeypot Trap", command=lambda: self.fill("GET /admin-backup HTTP/1.1")).pack(side="left", padx=5)

    def create_header(self, text):
        header = tk.Frame(self, bg=HEADER_BG, height=60)
        header.pack(fill="x")
        tk.Button(header, text="⬅ Home", bg=NAV_BTN_COLOR, fg="white", 
                  command=lambda: self.controller.show_frame("HomePage")).pack(side="left", padx=10, pady=10)
        tk.Label(header, text=text, font=("Arial", 18, "bold"), bg=HEADER_BG, fg="white").pack(side="left", padx=20)

    def fill(self, text):
        self.payload_entry.delete("1.0", tk.END)
        self.payload_entry.insert("1.0", text)

    def send_request(self):
        ip = self.ip_entry.get()
        payload = self.payload_entry.get("1.0", tk.END).strip()
        
        if not ip or not payload:
            messagebox.showwarning("Error", "IP and Payload are required!")
            return

        status, reason, log_msg = self.controller.engine.inspect_request(ip, payload)
        
        if status == "BLOCKED":
            messagebox.showwarning("BLOCKED", f"Threat Detected:\n{reason}")
        else:
            messagebox.showinfo("ALLOWED", "Request passed security checks.")

class DashboardPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg="#ecf0f1")

        self.create_header("Live Security Dashboard")

        self.lbl_threat = tk.Label(self, text="THREAT LEVEL: LOW", font=("Arial", 14, "bold"), bg="#2ecc71", fg="white", pady=15)
        self.lbl_threat.pack(fill="x")

        stats_frame = tk.Frame(self, bg="#ecf0f1", pady=20)
        stats_frame.pack()

        self.lbl_total = self.create_card(stats_frame, "Total Requests", "0", 0, 0)
        self.lbl_blocked = self.create_card(stats_frame, "Blocked Requests", "0", 0, 1, "red")
        self.lbl_allowed = self.create_card(stats_frame, "Allowed Requests", "0", 0, 2, "green")
        
        self.lbl_sql = self.create_card(stats_frame, "SQLi Attempts", "0", 1, 0, "#d35400")
        self.lbl_xss = self.create_card(stats_frame, "XSS Attempts", "0", 1, 1, "#8e44ad")
        self.lbl_honey = self.create_card(stats_frame, "Honeypot Hits", "0", 1, 2, "#c0392b")

        tk.Button(self, text="🔄 Refresh Stats", font=("Arial", 12), command=self.update_view).pack(pady=20)

    def create_header(self, text):
        header = tk.Frame(self, bg=HEADER_BG)
        header.pack(fill="x")
        tk.Button(header, text="⬅ Home", bg=NAV_BTN_COLOR, fg="white", 
                  command=lambda: self.controller.show_frame("HomePage")).pack(side="left", padx=10, pady=10)
        tk.Label(header, text=text, font=("Arial", 18, "bold"), bg=HEADER_BG, fg="white").pack(side="left", padx=20)

    def create_card(self, parent, title, value, row, col, color="black"):
        frame = tk.Frame(parent, bg="white", width=220, height=120, padx=10, pady=10, relief="raised")
        frame.grid(row=row, column=col, padx=15, pady=15)
        frame.pack_propagate(False)
        
        tk.Label(frame, text=title, font=("Arial", 10), bg="white", fg="#7f8c8d").pack()
        lbl_value = tk.Label(frame, text=value, font=("Arial", 28, "bold"), bg="white", fg=color)
        lbl_value.pack(expand=True)
        return lbl_value

    def update_view(self):
        stats = self.controller.engine.stats
        
        self.lbl_total.config(text=stats['total_requests'])
        self.lbl_blocked.config(text=stats['blocked'])
        self.lbl_allowed.config(text=stats['allowed'])
        self.lbl_sql.config(text=stats['sql_attempts'])
        self.lbl_xss.config(text=stats['xss_attempts'])
        self.lbl_honey.config(text=stats['honeypot_hits'])

        blocked = stats['blocked']
        if blocked >= 10:
            self.lbl_threat.config(text="THREAT LEVEL: CRITICAL", bg="#c0392b")
        elif blocked >= 5:
            self.lbl_threat.config(text="THREAT LEVEL: ELEVATED", bg="#f39c12")
        else:
            self.lbl_threat.config(text="THREAT LEVEL: LOW", bg="#2ecc71")

class LogsPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.configure(bg="#ecf0f1")

        self.create_header("System Logs & Reports")

        log_frame = tk.Frame(self, bg="white", padx=10, pady=10)
        log_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        tk.Label(log_frame, text="Recent Activity Log:", bg="white", font=("Arial", 12, "bold")).pack(anchor="w")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, pady=5)
        
        btn = tk.Button(self, text="📄 Export Full Report to CSV", bg="#27ae60", fg="white", font=("Arial", 12, "bold"),
                        command=self.export_csv, cursor="hand2")
        btn.pack(pady=10)

    def create_header(self, text):
        header = tk.Frame(self, bg=HEADER_BG)
        header.pack(fill="x")
        tk.Button(header, text="⬅ Home", bg=NAV_BTN_COLOR, fg="white", 
                  command=lambda: self.controller.show_frame("HomePage")).pack(side="left", padx=10, pady=10)
        tk.Label(header, text=text, font=("Arial", 18, "bold"), bg=HEADER_BG, fg="white").pack(side="left", padx=20)

    def update_view(self):
        self.log_text.delete("1.0", tk.END)
        try:
            with open("sentinel_log.txt", "r") as f:
                content = f.read()
                self.log_text.insert(tk.END, content)
                self.log_text.see(tk.END)
        except FileNotFoundError:
            self.log_text.insert(tk.END, "No logs found yet.")

    def export_csv(self):
        filename = f"Sentinel_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Metric", "Count"])
                for key, value in self.controller.engine.stats.items():
                    writer.writerow([key, value])
            messagebox.showinfo("Success", f"Report saved:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = SentinelApp()
    app.mainloop()